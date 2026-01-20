package bootstrap

import (
	"context"
	"fmt"
	"net/http"

	"user-service/internal/application/auth"
	"user-service/internal/infrastructure/config"
	"user-service/internal/infrastructure/db/postgres"
	"user-service/internal/infrastructure/security/jwt"
	oauthpkg "user-service/internal/infrastructure/security/oauth"
	"user-service/internal/transport/http/handlers"
	"user-service/internal/transport/http/middleware"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type App struct {
	cfg    *config.Config
	logger *zap.Logger
	server *http.Server
	pool   *pgxpool.Pool
}

func New(ctx context.Context, configPath string, logger *zap.Logger) (*App, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	logger.Info("configuration loaded",
		zap.Int("server_port", cfg.Server.Port),
		zap.String("db_host", cfg.Database.Host),
	)

	jwtProvider, err := jwt.NewProvider(jwt.Config{
		Secret:          cfg.JWT.Secret,
		AccessTokenTTL:  cfg.JWT.AccessTokenTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT provider: %w", err)
	}

	dsn := cfg.DatabaseDSN()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	logger.Info("database connection established")

	queries := postgres.New(pool)

	authService := auth.NewAuthService(queries, jwtProvider, logger)

	stateStorage := oauthpkg.NewMemoryStateStorage()
	oauthConfig := &oauth2.Config{
		ClientID:     cfg.OAuth.Google.ClientID,
		ClientSecret: cfg.OAuth.Google.ClientSecret,
		RedirectURL:  cfg.OAuth.Google.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
	oauthService := auth.NewOAuthService(oauthConfig, stateStorage, queries, jwtProvider, logger)

	router := buildRouter(authService, oauthService, jwtProvider, logger, pool)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return &App{
		cfg:    cfg,
		logger: logger,
		server: server,
		pool:   pool,
	}, nil
}

func (a *App) Run() error {
	a.logger.Info("starting HTTP server", zap.String("addr", a.server.Addr))
	return a.server.ListenAndServe()
}

func (a *App) Shutdown(ctx context.Context) error {
	a.logger.Info("shutting down gracefully...")

	if err := a.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	a.pool.Close()
	a.logger.Info("database connection closed")

	return nil
}

func buildRouter(
	authService *auth.AuthService,
	oauthService *auth.OAuthService,
	jwtProvider *jwt.Provider,
	logger *zap.Logger,
	pool *pgxpool.Pool,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/health/db", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	oauthHandlers := handlers.NewOAuthHandlers(oauthService, logger)

	authMiddleware := middleware.Auth(jwtProvider, logger)

	mux.HandleFunc("/api/auth/register", handlers.MakeRegisterHandler(authService, logger))
	mux.HandleFunc("/api/auth/login", handlers.MakeLoginHandler(authService, logger))
	mux.HandleFunc("/api/auth/refresh", handlers.MakeRefreshHandler(authService, logger))

	mux.HandleFunc("/api/auth/google/login", oauthHandlers.GoogleLogin)
	mux.HandleFunc("/api/auth/google/callback", oauthHandlers.GoogleCallback)

	mux.Handle("/api/auth/logout", authMiddleware(handlers.MakeLogoutHandler(authService, logger)))
	mux.Handle("/api/auth/me", authMiddleware(handlers.MakeMeHandler(authService, logger)))
	mux.Handle("/api/auth/assign-role", authMiddleware(handlers.MakeAssignRoleHandler(authService, logger)))

	return mux
}
