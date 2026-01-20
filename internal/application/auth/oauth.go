package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"user-service/internal/infrastructure/db/postgres"
	"user-service/internal/infrastructure/security/jwt"
	"user-service/internal/infrastructure/security/oauth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type OAuthService struct {
	oauthConfig  *oauth2.Config
	stateStorage *oauth.MemoryStateStorage
	queries      *postgres.Queries
	jwtProvider  *jwt.Provider
	logger       *zap.Logger
}

func NewOAuthService(
	oauthConfig *oauth2.Config,
	stateStorage *oauth.MemoryStateStorage,
	queries *postgres.Queries,
	jwtProvider *jwt.Provider,
	logger *zap.Logger,
) *OAuthService {
	return &OAuthService{
		oauthConfig:  oauthConfig,
		stateStorage: stateStorage,
		queries:      queries,
		jwtProvider:  jwtProvider,
		logger:       logger,
	}
}

func (s *OAuthService) AuthURL(ip, userAgent string) (string, error) {
	state, err := generateSecureState(32)
	if err != nil {
		s.logger.Error("failed to generate oauth state", zap.Error(err))
		return "", err
	}

	meta := oauth.StateMetadata{
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	s.stateStorage.Save(state, meta)

	url := s.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	s.logger.Info("OAuth redirect URL generated", zap.String("state", state))

	return url, nil
}

func (s *OAuthService) HandleCallback(ctx context.Context, req OAuthCallbackRequest) (*AuthResponse, error) {
	if req.State == "" || req.Code == "" {
		s.logger.Warn("invalid callback: missing state or code")
		return nil, errors.New("missing state or code")
	}

	meta, ok := s.stateStorage.Get(req.State)
	if !ok {
		s.logger.Warn("invalid oauth state", zap.String("state", req.State))
		return nil, ErrInvalidOAuthState
	}
	s.logger.Info("oauth state validated", zap.Any("meta", meta))
	s.stateStorage.Delete(req.State)

	token, err := s.oauthConfig.Exchange(ctx, req.Code)
	if err != nil {
		s.logger.Error("oauth exchange failed", zap.Error(err))
		return nil, ErrOAuthExchangeFailed
	}
	s.logger.Info("oauth token received")

	email, err := s.fetchGoogleEmail(ctx, token)
	if err != nil {
		s.logger.Error("failed to fetch profile", zap.Error(err))
		return nil, ErrFailedToFetchProfile
	}
	email = strings.ToLower(strings.TrimSpace(email))
	s.logger.Info("google email fetched", zap.String("email", email))

	userID, err := s.getOrCreateOAuthUser(ctx, email)
	if err != nil {
		return nil, err
	}

	roles, err := s.queries.GetRolesByUserId(ctx, userID)
	if err != nil || len(roles) == 0 {
		s.logger.Info("no roles found, defaulting to 'user'")
		roles = []string{"user"}
	}
	s.logger.Info("roles assigned", zap.Strings("roles", roles))

	accessToken, err := s.jwtProvider.GenerateAccessToken(userID, roles)
	if err != nil {
		s.logger.Error("failed to generate access token", zap.Error(err))
		return nil, err
	}

	refreshToken, err := s.jwtProvider.GenerateRefreshToken(userID, roles)
	if err != nil {
		s.logger.Error("failed to generate refresh token", zap.Error(err))
		return nil, err
	}

	s.logger.Info("tokens generated successfully")

	_, err = s.queries.CreateRefreshToken(ctx, postgres.CreateRefreshTokenParams{
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(s.jwtProvider.RefreshTokenTTL()), Valid: true},
	})
	if err != nil {
		s.logger.Error("failed to save refresh token", zap.Error(err))
		return nil, err
	}

	s.logger.Info("refresh token saved to DB")

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *OAuthService) getOrCreateOAuthUser(ctx context.Context, email string) (int32, error) {
	userByEmail, err := s.queries.GetUserByEmail(ctx, email)
	if err == nil {
		s.logger.Info("existing user found",
			zap.Int32("user_id", userByEmail.ID),
			zap.String("email", userByEmail.Email))
		return userByEmail.ID, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		s.logger.Info("user not found, creating new OAuth user", zap.String("email", email))

		createdUser, err := s.queries.CreateUser(ctx, postgres.CreateUserParams{
			Email:    email,
			Password: pgtype.Text{String: "", Valid: true},
		})
		if err != nil {
			s.logger.Error("failed to create OAuth user", zap.Error(err))
			userByEmail, err = s.queries.GetUserByEmail(ctx, email)
			if err != nil {
				return 0, err
			}
			return userByEmail.ID, nil
		}

		s.logger.Info("new OAuth user created",
			zap.Int32("user_id", createdUser.ID),
			zap.String("email", createdUser.Email))
		return createdUser.ID, nil
	}

	s.logger.Error("failed to get user by email", zap.Error(err))
	return 0, err
}

func (s *OAuthService) fetchGoogleEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Email, nil
}

func generateSecureState(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
