package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"user-service/internal/db"
	"user-service/internal/auth"

	"github.com/jackc/pgconn"
	"go.uber.org/zap"
)

// helper: пишет JSON-ответ с нужным статусом
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// makeRegisterHandler создает пользователя, возвращает JWT
func makeRegisterHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Разрешаем только POST
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Ограничиваем размер тела, чтобы избежать DoS по памяти
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

		// Простая валидация
		req.Email = strings.TrimSpace(req.Email)
		if req.Email == "" || !strings.Contains(req.Email, "@") {
			writeError(w, http.StatusBadRequest, "invalid email")
			return
		}
		if len(req.Password) < 6 {
			writeError(w, http.StatusBadRequest, "password too short (min 6 chars)")
			return
		}

		ctx := r.Context()

		// Хэшируем пароль
		hashed, err := auth.HashPassword(req.Password)
		if err != nil {
			logger.Error("failed to hash password", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// Создаем пользователя
		user, err := q.CreateUser(ctx, db.CreateUserParams{
			Email:    req.Email,
			Password: hashed,
		})
		if err != nil {
			// Проверяем специфическую ошибку Postgres (unique violation)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				logger.Info("attempt to create duplicate user", zap.String("email", req.Email))
				writeError(w, http.StatusConflict, "email already in use")
				return
			}

			// Если sql.ErrNoRows или другие ошибки — логируем и возвращаем 500
			if errors.Is(err, sql.ErrNoRows) {
				logger.Error("create user returned no rows", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			logger.Error("failed to create user", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// Получаем роли пользователя (если ничего не назначено — ставим роль по умолчанию в токене)
		roles, err := q.GetRolesByUserId(ctx, user.ID)
		if err != nil {
			logger.Error("failed to get roles for new user", zap.Int32("user_id", user.ID), zap.Error(err))
			// не фатал, но логируем и продолжаем — выдадим токен с дефолтной ролью
			roles = []string{"user"}
		}
		if len(roles) == 0 {
			roles = []string{"user"}
		}

		// Генерируем JWT
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

// makeLoginHandler логинит пользователя и возвращает JWT
func makeLoginHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Разрешаем только POST
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Ограничиваем тело
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

		// Получаем пользователя по email
		user, err := q.GetUserByEmail(ctx, req.Email)
		if err != nil {
			// Не раскрываем, что именно не так — просто отвечаем Unauthorized
			logger.Info("login failed - user not found or db error", zap.String("email", req.Email), zap.Error(err))
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Проверяем пароль
		if err := auth.CheckPassword(user.Password, req.Password); err != nil {
			logger.Info("login failed - invalid password", zap.String("email", req.Email))
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Роли и токен
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

// makeMeHandler возвращает инфо о пользователе по claims из контекста
func makeMeHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Извлекаем claims безопасно
		val := r.Context().Value("claims")
		if val == nil {
			writeError(w, http.StatusUnauthorized, "missing token claims")
			return
		}
		claims, ok := val.(map[string]interface{})
		if !ok {
			logger.Warn("claims type assertion failed")
			writeError(w, http.StatusUnauthorized, "invalid token claims")
			return
		}

		// Аккуратно парсим user_id (поддерживаем float64 и string)
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
				// пытаемся распарсить строку в число
				// (не импортируем strconv для простоты — можно добавить при необходимости)
				logger.Warn("user_id is string in claims; unsupported parsing")
				writeError(w, http.StatusUnauthorized, "invalid token claims")
				return
			default:
				writeError(w, http.StatusUnauthorized, "invalid token claims")
				return
			}
		} else {
			writeError(w, http.StatusUnauthorized, "user_id not found in token")
			return
		}

		ctx := r.Context()
		user, err := q.GetUserById(ctx, userID)
		if err != nil {
			// Если пользователь не найден — 404, иначе 500
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
