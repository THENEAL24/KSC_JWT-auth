package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"user-service/internal/application/auth"
	"user-service/internal/transport/http/middleware"

	"go.uber.org/zap"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func MakeRegisterHandler(authService *auth.AuthService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("register request", zap.String("method", r.Method), zap.String("path", r.URL.Path))

		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := dec.Decode(&reqBody); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		resp, err := authService.Register(r.Context(), auth.RegisterRequest{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			handleServiceError(w, err, logger)
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
		})
	}
}

func MakeLoginHandler(authService *auth.AuthService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("login request", zap.String("method", r.Method), zap.String("path", r.URL.Path))

		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := dec.Decode(&reqBody); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		resp, err := authService.Login(r.Context(), auth.LoginRequest{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			handleServiceError(w, err, logger)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
		})
	}
}

func MakeLogoutHandler(authService *auth.AuthService, logger *zap.Logger) http.HandlerFunc {
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

		err := authService.Logout(r.Context(), auth.LogoutRequest{
			RefreshToken: tokenStr,
		})
		if err != nil {
			handleServiceError(w, err, logger)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func MakeMeHandler(authService *auth.AuthService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("me request", zap.String("method", r.Method), zap.String("path", r.URL.Path))

		claims, ok := middleware.ClaimsFromContext(r.Context())
		if !ok {
			logger.Warn("missing claims in context")
			writeError(w, http.StatusUnauthorized, "missing token claims")
			return
		}

		resp, err := authService.UserInfo(r.Context(), claims)
		if err != nil {
			handleServiceError(w, err, logger)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func MakeAssignRoleHandler(authService *auth.AuthService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("assign role request", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		if r.Method != http.MethodPost {
			logger.Warn("method not allowed", zap.String("handler", "assign_role"), zap.String("method", r.Method))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

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

		claims, ok := middleware.ClaimsFromContext(r.Context())
		if !ok {
			logger.Warn("missing claims in context")
			writeError(w, http.StatusUnauthorized, "missing token claims")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var reqBody struct {
			RoleID int32 `json:"role_id"`
		}
		if err := dec.Decode(&reqBody); err != nil || reqBody.RoleID <= 0 {
			logger.Warn("invalid request body for assign role", zap.Error(err), zap.Int32("role_id", reqBody.RoleID))
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		err = authService.AssignRole(r.Context(), claims, auth.AssignRoleRequest{
			UserID: int32(userID64),
			RoleID: reqBody.RoleID,
		})
		if err != nil {
			handleServiceError(w, err, logger)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func MakeRefreshHandler(authService *auth.AuthService, logger *zap.Logger) http.HandlerFunc {
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

		resp, err := authService.Refresh(r.Context(), auth.RefreshRequest{
			RefreshToken: tokenStr,
		})
		if err != nil {
			handleServiceError(w, err, logger)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
		})
	}
}

func handleServiceError(w http.ResponseWriter, err error, logger *zap.Logger) {
	switch err {
	case auth.ErrInvalidEmail:
		writeError(w, http.StatusBadRequest, "invalid email")
	case auth.ErrPasswordTooShort:
		writeError(w, http.StatusBadRequest, "password too short (min 6 chars)")
	case auth.ErrUserAlreadyExists:
		writeError(w, http.StatusConflict, "user already exists")
	case auth.ErrInvalidCredentials:
		writeError(w, http.StatusUnauthorized, "invalid credentials")
	case auth.ErrUserNotFound:
		writeError(w, http.StatusNotFound, "user not found")
	case auth.ErrInvalidToken:
		writeError(w, http.StatusUnauthorized, "invalid token")
	case auth.ErrTokenExpired:
		writeError(w, http.StatusUnauthorized, "token expired")
	case auth.ErrMissingToken:
		writeError(w, http.StatusUnauthorized, "missing token")
	case auth.ErrInvalidClaims:
		writeError(w, http.StatusUnauthorized, "invalid token claims")
	case auth.ErrForbidden:
		writeError(w, http.StatusForbidden, "forbidden")
	case auth.ErrInvalidOAuthState:
		writeError(w, http.StatusUnauthorized, "invalid oauth state")
	case auth.ErrOAuthExchangeFailed:
		writeError(w, http.StatusUnauthorized, "oauth exchange failed")
	case auth.ErrFailedToFetchProfile:
		writeError(w, http.StatusUnauthorized, "failed to fetch profile")
	default:
		logger.Error("internal error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
