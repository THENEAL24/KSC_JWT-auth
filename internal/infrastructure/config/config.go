package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
}

type ServerConfig struct {
	Port            int
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string `mapstructure:"ssl_mode"`
}

type JWTConfig struct {
	Secret          string
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
}

type OAuthConfig struct {
	Google GoogleOAuthConfig
}

type GoogleOAuthConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

func LoadConfig(path string) (*Config, error) {
	_ = godotenv.Load()

	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := loadFromEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to load from env: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

func loadFromEnv(cfg *Config) error {
	if port := os.Getenv("PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("invalid PORT: %w", err)
		}
		cfg.Server.Port = p
	}

	if host := os.Getenv("DB_HOST"); host != "" {
		cfg.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("invalid DB_PORT: %w", err)
		}
		cfg.Database.Port = p
	}
	if user := os.Getenv("DB_USER"); user != "" {
		cfg.Database.User = user
	}
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		cfg.Database.Password = password
	}
	if database := os.Getenv("DB_NAME"); database != "" {
		cfg.Database.Database = database
	}
	if sslMode := os.Getenv("DB_SSL_MODE"); sslMode != "" {
		cfg.Database.SSLMode = sslMode
	}

	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		cfg.JWT.Secret = secret
	}

	if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		cfg.OAuth.Google.ClientID = clientID
	}
	if clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); clientSecret != "" {
		cfg.OAuth.Google.ClientSecret = clientSecret
	}
	if redirectURL := os.Getenv("GOOGLE_REDIRECT_URI"); redirectURL != "" {
		cfg.OAuth.Google.RedirectURL = redirectURL
	}

	return nil
}

func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", c.Database.Port)
	}
	if c.Database.User == "" {
		return fmt.Errorf("database user is required")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("database name is required")
	}

	if c.JWT.Secret == "" {
		return fmt.Errorf("JWT secret is required")
	}
	if len(c.JWT.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters")
	}
	if c.JWT.AccessTokenTTL <= 0 {
		return fmt.Errorf("invalid JWT access token TTL")
	}
	if c.JWT.RefreshTokenTTL <= 0 {
		return fmt.Errorf("invalid JWT refresh token TTL")
	}

	if c.OAuth.Google.ClientID != "" {
		if c.OAuth.Google.ClientSecret == "" {
			return fmt.Errorf("Google OAuth client secret is required when client ID is set")
		}
		if c.OAuth.Google.RedirectURL == "" {
			return fmt.Errorf("Google OAuth redirect URL is required when client ID is set")
		}
	}

	return nil
}

func (c *Config) DatabaseDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Database,
		c.Database.SSLMode,
	)
}
