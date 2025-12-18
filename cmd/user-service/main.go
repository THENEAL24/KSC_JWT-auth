package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"user-service/internal/auth"
	"user-service/internal/db"
	appLogger "user-service/internal/logger"
	"user-service/internal/server"
	"user-service/internal/config"

	"github.com/joho/godotenv"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadConfig("config/config.yml")
    if err != nil {
        log.Fatalf("Ошибка загрузки конфига: %v", err)
    }

	logger := appLogger.New()
	defer logger.Sync()

	godotenv.Load()
	if err := auth.InitJWTSecret(cfg); err != nil {
		logger.Fatal("failed to init JWT secret", zap.Error(err))
	}

	dsn := os.Getenv("DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/usersdb?sslmode=disable"
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Fatal("failed to connect Postgres", zap.Error(err))
	}
	defer pool.Close()

	queries := db.New(pool)

	stateStorage := auth.NewMemoryStateStorage()

	oauthHandlers := server.NewOAuthHandlers(queries, stateStorage, logger)

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "pong")
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("healthz", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

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

	authMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("auth middleware", zap.String("method", r.Method), zap.String("path", r.URL.Path))
			authHeader := r.Header.Get("Authorization")
			if strings.TrimSpace(authHeader) == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing Authorization header"})
				return
			}
			claims, err := auth.ParseJWT(authHeader)
			if err != nil {
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

	http.HandleFunc("/auth/refresh", server.MakeRefreshHandler(queries, logger))
	http.HandleFunc("/auth/logout", server.MakeLogoutHandler(queries, logger))

	http.HandleFunc("/auth/google", oauthHandlers.GoogleLogin)
	http.HandleFunc("/auth/google/callback", oauthHandlers.GoogleCallback)

	addr := ":8080"
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		if !strings.HasPrefix(p, ":") {
			addr = ":" + p
		} else {
			addr = p
		}
	}

	logger.Info("starting server", zap.String("addr", addr))
	srv := &http.Server{
        Addr:         addr,
        Handler:      http.DefaultServeMux,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
	
	quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        log.Printf("Сервер слушает %s", addr)
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Ошибка запуска сервера: %v", err)
        }
    }()

    <-quit
    log.Println("Получен сигнал завершения, выключение сервера...")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatalf("Ошибка graceful shutdown: %v", err)
    }

    log.Println("Сервер успешно завершил работу")
}
