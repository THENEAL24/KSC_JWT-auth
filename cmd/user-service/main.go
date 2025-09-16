package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
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
	dsn := "postgres://postgres:postgres@localhost:5432/usersdb?sslmode=disable"
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

	http.HandleFunc("/register", server.MakeRegisterHandler(queries, logger))
	http.HandleFunc("/login", server.MakeLoginHandler(queries, logger))

	// JWT middleware
	authMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("auth middleware", zap.String("method", r.Method), zap.String("path", r.URL.Path))
			authHeader := r.Header.Get("Authorization")
			if strings.TrimSpace(authHeader) == "" {
				logger.Warn("missing Authorization header")
				http.Error(w, "missing Authorization header", http.StatusUnauthorized)
				return
			}
			claims, err := auth.ParseJWT(authHeader)
			if err != nil {
				logger.Warn("invalid token", zap.Error(err))
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			newCtx := context.WithValue(r.Context(), "claims", map[string]interface{}(claims))
			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}

	http.Handle("/me", authMW(http.HandlerFunc(server.MakeMeHandler(queries, logger))))
	http.Handle("/users/", authMW(http.HandlerFunc(server.MakeAssignRoleHandler(queries, logger))))

	logger.Info("starting server", zap.String("addr", ":8080"))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
