package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"user-service/internal/app"
	appLogger "user-service/pkg/logger"
)

func main() {
	configPath := flag.String("config", "config/config.yml", "path to config file")
	flag.Parse()

	logger := appLogger.New()
	defer logger.Sync()

	ctx := context.Background()
	application, err := app.New(ctx, *configPath, logger)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := application.Run(); err != nil {
			log.Fatalf("Failed to run application: %v", err)
		}
	}()

	<-quit
	logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Failed to shutdown gracefully: %v", err)
	}

	logger.Info("application stopped successfully")
}
