package service

import (
	"encoding/json"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"errors"
	"time"
	"user-service/internal/auth"
	"user-service/internal/db"

	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

var req struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var resp  struct {
	ID    int32  `json:"id"`
	Email string `json:"email"`	
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func Register(q *db.Queries, logger *zap.Logger, w http.ResponseWriter, r *http.Request) (string, string) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return "", ""
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "invalid email")
		return "", ""
	}
	if len(req.Password) < 6 {
		writeError(w, http.StatusBadRequest, "password too short (min 6 chars)")
		return "", ""
	}

	ctx := r.Context()

	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		logger.Error("failed to hash password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	user, err := q.CreateUser(ctx, db.CreateUserParams{
		Email:    req.Email,
		Password: pgtype.Text{String: hashed, Valid: true},
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusConflict, "user already exists")
			return "", ""
		}
		logger.Error("failed to create user", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	roles, err := q.GetRolesByUserId(ctx, user.ID)
	if err != nil || len(roles) == 0 {
		roles = []string{"user"}
	}

	accessToken, err := auth.GenerateJWT(user.ID, roles)
	if err != nil {
		logger.Error("failed to generate access token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	refreshToken, err := auth.GenerateJWT(user.ID, roles)
	if err != nil {
		logger.Error("failed to generate refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	_, err = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(30 * 24 * time.Hour), Valid: true},
	})
	if err != nil {
		logger.Error("failed to store refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	return accessToken, refreshToken
}

func Login(q *db.Queries, logger *zap.Logger, w http.ResponseWriter, r *http.Request) (string, string) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return "", ""
	}

	ctx := r.Context()

	user, err := q.GetUserByEmail(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return "", ""
	}

	if err := auth.CheckPassword(user.Password.String, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return "", ""
	}

	roles, err := q.GetRolesByUserId(ctx, user.ID)
	if err != nil || len(roles) == 0 {
		roles = []string{"user"}
	}

	accessToken, err := auth.GenerateJWT(user.ID, roles)
	if err != nil {
		logger.Error("failed to generate access token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	refreshToken, err := auth.GenerateJWT(user.ID, roles)
	if err != nil {
		logger.Error("failed to generate refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	_, err = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(30 * 24 * time.Hour), Valid: true},
	})
	if err != nil {
		logger.Error("failed to store refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	return accessToken, refreshToken
}

func Logout(q *db.Queries, logger *zap.Logger, w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		logger.Warn("missing authorization header in logout")
		writeError(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	tokenStr := authHeader
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}
	
	claims, err := auth.ParseJWT(tokenStr)
	if err != nil {
		logger.Warn("invalid refresh token on logout", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	rawID, ok := claims["user_id"]
	if !ok {
		logger.Warn("user_id missing in refresh token claims")
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	var userID int32
	switch v := rawID.(type) {
		case float64:
			userID = int32(v)
		case int32:
			userID = v
		case int64:
			userID = int32(v)
		default:
			writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	ctx := r.Context()

	ref, err := q.GetRefreshTokenByToken(ctx, tokenStr)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Warn("refresh token not found or already revoked",
				zap.Int32("user_id", userID),
			)
			writeError(w, http.StatusUnauthorized, "invalid refresh token")
			return
		}
		logger.Error("failed to load refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !ref.ExpiresAt.Valid || time.Now().After(ref.ExpiresAt.Time) {
		logger.Info("refresh token expired",
			zap.Int32("user_id", ref.UserID),
		)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err := q.RevokeRefreshToken(ctx, tokenStr); err != nil {
		logger.Error("failed to revoke refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	logger.Info("user logged out",
		zap.Int32("user_id", userID),
	)
}

func Me(q *db.Queries, logger *zap.Logger, w http.ResponseWriter, r *http.Request) (int32, string) {
	val := r.Context().Value("claims")
	if val == nil {
		logger.Warn("missing claims in context")
		writeError(w, http.StatusUnauthorized, "missing token claims")
		return 0, ""
	}
	claims, ok := val.(map[string]interface{})
	if !ok {
		logger.Warn("claims type assertion failed")
		writeError(w, http.StatusUnauthorized, "invalid token claims")
		return 0, ""
	}

	var userID int32
	if uidRaw, exists := claims["user_id"]; exists {
		switch v := uidRaw.(type) {
		case float64:
			userID = int32(v)
		case float32:
			userID = int32(v)
		case int:
			userID = int32(v)
		case int32:
			userID = v
		case int64:
			userID = int32(v)
		case string:
			logger.Warn("user_id is string in claims; unsupported parsing")
			writeError(w, http.StatusUnauthorized, "invalid token claims")
			return 0, ""
		default:
			writeError(w, http.StatusUnauthorized, "invalid token claims")
			return 0, ""
		}
	} else {
		logger.Warn("user_id not found in token claims")
		writeError(w, http.StatusUnauthorized, "user_id not found in token")
		return 0, ""
	}

	ctx := r.Context()
	user, err := q.GetUserById(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "user not found")
			return 0, ""
		}
		logger.Error("failed to get user by id", zap.Int32("user_id", userID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return 0, ""
	}

	return user.ID, user.Email
}

func AssignRole(q *db.Queries, logger *zap.Logger, w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[1] != "users" || parts[3] != "roles" {
		logger.Warn("invalid assign role path", zap.String("path", r.URL.Path))
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	userID64, err := strconv.ParseInt(parts[2], 10, 32)
	if err != nil || userID64 <= 0 {
		logger.Warn("invalid user id in path", zap.String("segment", parts[2]))
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	val := r.Context().Value("claims")
	claims, _ := val.(map[string]interface{})
	if !claimsHasRole(claims, "admin") {
		logger.Warn("forbidden: missing admin role", zap.Any("claims_roles", claims["roles"]))
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req struct {
		RoleID int32 `json:"role_id"`
	}
	if err := dec.Decode(&req); err != nil || req.RoleID <= 0 {
		logger.Warn("invalid request body for assign role", zap.Error(err), zap.Int32("role_id", req.RoleID))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	if err := q.AssignRole(ctx, db.AssignRoleParams{UserID: int32(userID64), RoleID: req.RoleID}); err != nil {
		logger.Error("failed to assign role", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
}

func Refresh(q *db.Queries, logger *zap.Logger, w http.ResponseWriter, r *http.Request) (string, string) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeError(w, http.StatusUnauthorized, "missing refresh token")
		return "", ""
	}

	tokenStr := authHeader
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}

	ref, err := q.GetRefreshTokenByToken(r.Context(), tokenStr)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Warn("refresh token not found or revoked")
			writeError(w, http.StatusUnauthorized, "invalid refresh token")
			return "", ""
		}
		logger.Error("failed to query refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	if !ref.ExpiresAt.Valid || time.Now().After(ref.ExpiresAt.Time) {
		logger.Info("refresh token expired",
			zap.Int("refresh_token_id", int(ref.ID)),
		)
		_ = q.RevokeRefreshToken(r.Context(), tokenStr)
		writeError(w, http.StatusUnauthorized, "refresh token expired")
		return "", ""
	}

	ctx := r.Context()

	user, err := q.GetUserById(ctx, ref.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusUnauthorized, "user not found")
			return "", ""
		}
		logger.Error("failed to get user for refresh", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	roles, err := q.GetRolesByUserId(ctx, user.ID)
	if err != nil || len(roles) == 0 {
		roles = []string{"user"}
	}

	accessToken, err := auth.GenerateJWT(user.ID, roles)
	if err != nil {
		logger.Error("failed to generate access token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	if err := q.RevokeRefreshToken(ctx, tokenStr); err != nil {
		logger.Error("failed to revoke old refresh token", zap.Error(err))
	}

	newRefreshToken, err := auth.GenerateJWT(user.ID, roles)
	if err != nil {
		logger.Error("failed to generate new refresh token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	_, err = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID: user.ID,
		Token:  newRefreshToken,
		ExpiresAt: pgtype.Timestamp{
			Time:  time.Now().Add(30 * 24 * time.Hour),
			Valid: true,
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", ""
	}

	return accessToken, newRefreshToken
}

func claimsHasRole(claims map[string]interface{}, role string) bool {
	if claims == nil {
		return false
	}
	raw, ok := claims["roles"]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case []interface{}:
		for _, r := range v {
			if rs, ok := r.(string); ok && rs == role {
				return true
			}
		}
	case []string:
		for _, rs := range v {
			if rs == role {
				return true
			}
		}
	case string:
		return v == role
	}
	return false
}
