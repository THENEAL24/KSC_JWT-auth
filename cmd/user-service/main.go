package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"user-service/internal/auth"
	"user-service/internal/db"
	appLogger "user-service/internal/logger"
	"user-service/internal/server"

	"github.com/joho/godotenv"
)

func main() {
	ctx := context.Background()

	logger := appLogger.New()
	defer logger.Sync()

	// Env & JWT
	godotenv.Load()
	if err := auth.InitJWTSecret(); err != nil {
		logger.Fatal("failed to init JWT secret", zap.Error(err))
	}

	// Postgres connection
	dsn := os.Getenv("DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/usersdb?sslmode=disable"
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Fatal("failed to connect Postgres", zap.Error(err))
	}
	defer pool.Close()

	// sqlc repository
	queries := db.New(pool)

	// HTTP
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "pong")
	})

	// Liveness probe
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("healthz", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Readiness probe (checks DB)
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("readyz", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		if err := pool.Ping(r.Context()); err != nil {
			logger.Warn("readiness failed: db ping error", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "unready", "error": "db unreachable"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	http.HandleFunc("/register", server.MakeRegisterHandler(queries, logger))
	http.HandleFunc("/login", server.MakeLoginHandler(queries, logger))

	// JWT middleware
	authMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("auth middleware", zap.String("method", r.Method), zap.String("path", r.URL.Path))
			authHeader := r.Header.Get("Authorization")
			if strings.TrimSpace(authHeader) == "" {
				logger.Warn("missing Authorization header", zap.String("path", r.URL.Path))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing Authorization header"})
				return
			}
			claims, err := auth.ParseJWT(authHeader)
			if err != nil {
				logger.Warn("invalid token", zap.Error(err), zap.String("path", r.URL.Path))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
				return
			}
			newCtx := context.WithValue(r.Context(), "claims", map[string]interface{}(claims))
			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}

	http.Handle("/me", authMW(http.HandlerFunc(server.MakeMeHandler(queries, logger))))
	http.Handle("/users/", authMW(http.HandlerFunc(server.MakeAssignRoleHandler(queries, logger))))

	addr := ":8080"
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		if !strings.HasPrefix(p, ":") {
			addr = ":" + p
		} else {
			addr = p
		}
	}

	logger.Info("starting server", zap.String("addr", addr))
	log.Fatal(http.ListenAndServe(addr, nil))
}
