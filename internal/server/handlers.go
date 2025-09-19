package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"user-service/internal/auth"
	"user-service/internal/db"

	"github.com/jackc/pgconn"
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

func MakeRegisterHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("register request", zap.String("method", r.Method), zap.String("path", r.URL.Path))

		if r.Method != http.MethodPost {
			logger.Warn("method not allowed", zap.String("handler", "register"), zap.String("method", r.Method))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := dec.Decode(&req); err != nil {
			logger.Warn("invalid json in register", zap.Error(err))
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		req.Email = strings.TrimSpace(req.Email)
		if req.Email == "" || !strings.Contains(req.Email, "@") {
			logger.Warn("invalid email in register", zap.String("email", req.Email))
			writeError(w, http.StatusBadRequest, "invalid email")
			return
		}
		if len(req.Password) < 6 {
			logger.Warn("password too short in register", zap.Int("length", len(req.Password)))
			writeError(w, http.StatusBadRequest, "password too short (min 6 chars)")
			return
		}

		ctx := r.Context()

		hashed, err := auth.HashPassword(req.Password)
		if err != nil {
			logger.Error("failed to hash password", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		user, err := q.CreateUser(ctx, db.CreateUserParams{
			Email:    req.Email,
			Password: hashed,
		})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				logger.Info("attempt to create duplicate user", zap.String("email", req.Email))
				writeError(w, http.StatusConflict, "email already in use")
				return
			}

			if errors.Is(err, sql.ErrNoRows) {
				logger.Error("create user returned no rows", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			logger.Error("failed to create user", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		roles, err := q.GetRolesByUserId(ctx, user.ID)
		if err != nil {
			logger.Error("failed to get roles for new user", zap.Int32("user_id", user.ID), zap.Error(err))
			roles = []string{"user"}
		}
		if len(roles) == 0 {
			roles = []string{"user"}
		}

		token, err := auth.GenerateJWT(user.ID, roles)
		if err != nil {
			logger.Error("failed to generate jwt", zap.Int32("user_id", user.ID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		logger.Info("user registered", zap.Int32("id", user.ID), zap.String("email", user.Email))
		writeJSON(w, http.StatusCreated, map[string]string{"token": token})
	}
}

func MakeLoginHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("login request", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		if r.Method != http.MethodPost {
			logger.Warn("method not allowed", zap.String("handler", "login"), zap.String("method", r.Method))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := dec.Decode(&req); err != nil {
			logger.Warn("invalid json in login", zap.Error(err))
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		ctx := r.Context()

		user, err := q.GetUserByEmail(ctx, req.Email)
		if err != nil {
			logger.Info("login failed - user not found or db error", zap.String("email", req.Email), zap.Error(err))
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if err := auth.CheckPassword(user.Password, req.Password); err != nil {
			logger.Info("login failed - invalid password", zap.String("email", req.Email))
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		roles, err := q.GetRolesByUserId(ctx, user.ID)
		if err != nil {
			logger.Error("failed to get roles for login", zap.Int32("user_id", user.ID), zap.Error(err))
			roles = []string{"user"}
		}
		if len(roles) == 0 {
			roles = []string{"user"}
		}

		token, err := auth.GenerateJWT(user.ID, roles)
		if err != nil {
			logger.Error("failed to generate jwt", zap.Int32("user_id", user.ID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		logger.Info("user logged in", zap.Int32("id", user.ID), zap.String("email", user.Email))
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}

func MakeMeHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("me request", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		val := r.Context().Value("claims")
		if val == nil {
			logger.Warn("missing claims in context")
			writeError(w, http.StatusUnauthorized, "missing token claims")
			return
		}
		claims, ok := val.(map[string]interface{})
		if !ok {
			logger.Warn("claims type assertion failed")
			writeError(w, http.StatusUnauthorized, "invalid token claims")
			return
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
				return
			default:
				writeError(w, http.StatusUnauthorized, "invalid token claims")
				return
			}
		} else {
			logger.Warn("user_id not found in token claims")
			writeError(w, http.StatusUnauthorized, "user_id not found in token")
			return
		}

		ctx := r.Context()
		user, err := q.GetUserById(ctx, userID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusNotFound, "user not found")
				return
			}
			logger.Error("failed to get user by id", zap.Int32("user_id", userID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		resp := struct {
			ID    int32  `json:"id"`
			Email string `json:"email"`
		}{
			ID:    user.ID,
			Email: user.Email,
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func MakeAssignRoleHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
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

		writeJSON(w, http.StatusNoContent, nil)
	}
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
