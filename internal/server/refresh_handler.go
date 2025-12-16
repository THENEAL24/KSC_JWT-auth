package server

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"user-service/internal/auth"
	"user-service/internal/db"

	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func MakeRefreshHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("refresh request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
		)

		if r.Method != http.MethodPost {
			logger.Warn("method not allowed", zap.String("handler", "refresh"))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing refresh token")
			return
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
				return
			}
			logger.Error("failed to query refresh token", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if !ref.ExpiresAt.Valid || time.Now().After(ref.ExpiresAt.Time) {
			logger.Info("refresh token expired",
				zap.Int("refresh_token_id", int(ref.ID)),
			)
			_ = q.RevokeRefreshToken(r.Context(), tokenStr)
			writeError(w, http.StatusUnauthorized, "refresh token expired")
			return
		}

		ctx := r.Context()

		user, err := q.GetUserById(ctx, ref.UserID)
		if err != nil {
			if err == sql.ErrNoRows {
				writeError(w, http.StatusUnauthorized, "user not found")
				return
			}
			logger.Error("failed to get user for refresh", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		roles, err := q.GetRolesByUserId(ctx, user.ID)
		if err != nil || len(roles) == 0 {
			roles = []string{"user"}
		}

		accessToken, err := auth.GenerateJWT(user.ID, roles)
		if err != nil {
			logger.Error("failed to generate access token", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if err := q.RevokeRefreshToken(ctx, tokenStr); err != nil {
			logger.Error("failed to revoke old refresh token", zap.Error(err))
		}

		newRefreshToken, err := auth.GenerateJWT(user.ID, roles)
		if err != nil {
			logger.Error("failed to generate new refresh token", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
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
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
		})
	}
}
