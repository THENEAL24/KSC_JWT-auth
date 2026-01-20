package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"user-service/internal/infrastructure/db/postgres"
	"user-service/internal/infrastructure/security/jwt"
	"user-service/internal/infrastructure/security/password"

	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type AuthService struct {
	queries     *postgres.Queries
	jwtProvider *jwt.Provider
	logger      *zap.Logger
}

func NewAuthService(queries *postgres.Queries, jwtProvider *jwt.Provider, logger *zap.Logger) *AuthService {
	return &AuthService{
		queries:     queries,
		jwtProvider: jwtProvider,
		logger:      logger,
	}
}

func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*AuthResponse, error) {
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		return nil, ErrInvalidEmail
	}
	if len(req.Password) < 6 {
		return nil, ErrPasswordTooShort
	}

	hashed, err := password.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("failed to hash password", zap.Error(err))
		return nil, err
	}

	user, err := s.queries.CreateUser(ctx, postgres.CreateUserParams{
		Email:    req.Email,
		Password: pgtype.Text{String: hashed, Valid: true},
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, ErrUserAlreadyExists
		}
		s.logger.Error("failed to create user", zap.Error(err))
		return nil, err
	}

	roles, err := s.queries.GetRolesByUserId(ctx, user.ID)
	if err != nil || len(roles) == 0 {
		roles = []string{"user"}
	}

	accessToken, err := s.jwtProvider.GenerateAccessToken(user.ID, roles)
	if err != nil {
		s.logger.Error("failed to generate access token", zap.Error(err))
		return nil, err
	}

	refreshToken, err := s.jwtProvider.GenerateRefreshToken(user.ID, roles)
	if err != nil {
		s.logger.Error("failed to generate refresh token", zap.Error(err))
		return nil, err
	}

	_, err = s.queries.CreateRefreshToken(ctx, postgres.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(s.jwtProvider.RefreshTokenTTL()), Valid: true},
	})
	if err != nil {
		s.logger.Error("failed to store refresh token", zap.Error(err))
		return nil, err
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*AuthResponse, error) {
	user, err := s.queries.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := password.CheckPassword(user.Password.String, req.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	roles, err := s.queries.GetRolesByUserId(ctx, user.ID)
	if err != nil || len(roles) == 0 {
		roles = []string{"user"}
	}

	accessToken, err := s.jwtProvider.GenerateAccessToken(user.ID, roles)
	if err != nil {
		s.logger.Error("failed to generate access token", zap.Error(err))
		return nil, err
	}

	refreshToken, err := s.jwtProvider.GenerateRefreshToken(user.ID, roles)
	if err != nil {
		s.logger.Error("failed to generate refresh token", zap.Error(err))
		return nil, err
	}

	_, err = s.queries.CreateRefreshToken(ctx, postgres.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(s.jwtProvider.RefreshTokenTTL()), Valid: true},
	})
	if err != nil {
		s.logger.Error("failed to store refresh token", zap.Error(err))
		return nil, err
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, req LogoutRequest) error {
	claims, err := s.jwtProvider.ParseToken(req.RefreshToken)
	if err != nil {
		s.logger.Warn("invalid refresh token on logout", zap.Error(err))
		return ErrInvalidToken
	}

	ref, err := s.queries.GetRefreshTokenByToken(ctx, req.RefreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			s.logger.Warn("refresh token not found or already revoked", zap.Int32("user_id", claims.UserID))
			return ErrInvalidToken
		}
		s.logger.Error("failed to load refresh token", zap.Error(err))
		return err
	}

	if !ref.ExpiresAt.Valid || time.Now().After(ref.ExpiresAt.Time) {
		s.logger.Info("refresh token expired", zap.Int32("user_id", ref.UserID))
		return ErrTokenExpired
	}

	if err := s.queries.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
		s.logger.Error("failed to revoke refresh token", zap.Error(err))
		return err
	}

	s.logger.Info("user logged out", zap.Int32("user_id", claims.UserID))
	return nil
}

func (s *AuthService) UserInfo(ctx context.Context, claims *jwt.Claims) (*UserResponse, error) {
	if claims == nil {
		return nil, ErrInvalidClaims
	}

	user, err := s.queries.GetUserById(ctx, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		s.logger.Error("failed to get user by id", zap.Int32("user_id", claims.UserID), zap.Error(err))
		return nil, err
	}

	return &UserResponse{
		ID:    user.ID,
		Email: user.Email,
	}, nil
}

func (s *AuthService) AssignRole(ctx context.Context, claims *jwt.Claims, req AssignRoleRequest) error {
	if claims == nil {
		return ErrInvalidClaims
	}

	if !hasRole(claims.Roles, "admin") {
		s.logger.Warn("forbidden: missing admin role", zap.Strings("roles", claims.Roles))
		return ErrForbidden
	}

	if req.UserID <= 0 || req.RoleID <= 0 {
		return errors.New("invalid user_id or role_id")
	}

	if err := s.queries.AssignRole(ctx, postgres.AssignRoleParams{
		UserID: req.UserID,
		RoleID: req.RoleID,
	}); err != nil {
		s.logger.Error("failed to assign role", zap.Error(err))
		return err
	}

	return nil
}

func (s *AuthService) Refresh(ctx context.Context, req RefreshRequest) (*AuthResponse, error) {
	ref, err := s.queries.GetRefreshTokenByToken(ctx, req.RefreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			s.logger.Warn("refresh token not found or revoked")
			return nil, ErrInvalidToken
		}
		s.logger.Error("failed to query refresh token", zap.Error(err))
		return nil, err
	}

	if !ref.ExpiresAt.Valid || time.Now().After(ref.ExpiresAt.Time) {
		s.logger.Info("refresh token expired", zap.Int("refresh_token_id", int(ref.ID)))
		_ = s.queries.RevokeRefreshToken(ctx, req.RefreshToken)
		return nil, ErrTokenExpired
	}

	user, err := s.queries.GetUserById(ctx, ref.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		s.logger.Error("failed to get user for refresh", zap.Error(err))
		return nil, err
	}

	roles, err := s.queries.GetRolesByUserId(ctx, user.ID)
	if err != nil || len(roles) == 0 {
		roles = []string{"user"}
	}

	accessToken, err := s.jwtProvider.GenerateAccessToken(user.ID, roles)
	if err != nil {
		s.logger.Error("failed to generate access token", zap.Error(err))
		return nil, err
	}

	if err := s.queries.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
		s.logger.Error("failed to revoke old refresh token", zap.Error(err))
	}

	newRefreshToken, err := s.jwtProvider.GenerateRefreshToken(user.ID, roles)
	if err != nil {
		s.logger.Error("failed to generate new refresh token", zap.Error(err))
		return nil, err
	}

	_, err = s.queries.CreateRefreshToken(ctx, postgres.CreateRefreshTokenParams{
		UserID: user.ID,
		Token:  newRefreshToken,
		ExpiresAt: pgtype.Timestamp{
			Time:  time.Now().Add(s.jwtProvider.RefreshTokenTTL()),
			Valid: true,
		},
	})
	if err != nil {
		s.logger.Error("failed to store new refresh token", zap.Error(err))
		return nil, err
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
