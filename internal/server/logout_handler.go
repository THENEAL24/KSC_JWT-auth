package server

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"user-service/internal/auth"
	"user-service/internal/db"

	"go.uber.org/zap"
)

func MakeLogoutHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("logout request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
		)

		if r.Method != http.MethodPost {
			logger.Warn("method not allowed", zap.String("handler", "logout"))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

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

		w.WriteHeader(http.StatusNoContent)
	}
}
