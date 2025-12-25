package server

import (
	"encoding/json"
	"net/http"
	"user-service/internal/db"
	"user-service/internal/service"

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
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		accessToken, refreshToken := service.Register(q, logger, w, r)

		if accessToken == "" && refreshToken == "" {
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func MakeLoginHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("login request", zap.String("method", r.Method), zap.String("path", r.URL.Path))

		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		accessToken, refreshToken := service.Login(q, logger, w, r)

		if accessToken == "" && refreshToken == "" {
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func MakeMeHandler(q *db.Queries, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("me request", zap.String("method", r.Method), zap.String("path", r.URL.Path))

		id, email := service.Me(q, logger, w, r)
		if id == 0 && email == "" {
			return
		}
		resp := struct {
			ID    int32  `json:"id"`
			Email string `json:"email"`
		}{ID: id, Email: email}

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

		service.AssignRole(q, logger, w, r)

		writeJSON(w, http.StatusNoContent, nil)
	}
}
