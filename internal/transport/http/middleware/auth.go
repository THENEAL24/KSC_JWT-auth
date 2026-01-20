package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"user-service/internal/infrastructure/security/jwt"

	"go.uber.org/zap"
)

type contextKey string

const (
	ClaimsContextKey contextKey = "claims"
)

func Auth(jwtProvider *jwt.Provider, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.TrimSpace(authHeader) == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			claims, err := jwtProvider.ParseToken(authHeader)
			if err != nil {
				logger.Warn("invalid token", zap.Error(err))
				writeJSONError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClaimsFromContext(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*jwt.Claims)
	return claims, ok
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
