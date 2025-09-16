package main

import (
	"os"
    "context"
    "fmt"
    "log"
    "net/http"

    "github.com/jackc/pgx/v5/pgxpool"
    "go.uber.org/zap"

    "user-service/internal/db"
	"github.com/joho/godotenv"
)

func main() {
    ctx := context.Background()

    cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stdout"}
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalf("не удалось создать логгер: %v", err)
	}
	defer logger.Sync()

    // Подключение к Postgres
    dsn := "postgres://postgres:postgres@localhost:5432/usersdb?sslmode=disable"
    pool, err := pgxpool.New(ctx, dsn)
    if err != nil {
        logger.Fatal("не удалось подключиться к Postgres", zap.Error(err))
    }
    defer pool.Close()

    // Репозиторий sqlc
    queries := db.New(pool)

    // Тестовый вызов — создать пользователя
    user, err := queries.CreateUser(ctx, db.CreateUserParams{
        Email:    "test@example.com",
        Password: "hashedpass",
    })
    if err != nil {
        logger.Fatal("ошибка при создании пользователя", zap.Error(err))
    }
    logger.Info("Пользователь создан", zap.Int32("id", user.ID), zap.String("email", user.Email))

    // Минимальный сервер
    http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "pong")
    })

    logger.Info("Запускаю сервер на :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
