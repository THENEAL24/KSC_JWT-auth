package config

import (
    "github.com/spf13/viper"
)

type Config struct {
    Server struct {
        Port int
    }
    Database struct {
        URL string
    }
    JWT struct {
        AccessTokenTTL string `mapstructure:"access_token_ttl"`
    }
}

func LoadConfig(path string) (*Config, error) {
    viper.SetConfigFile(path)
    if err := viper.ReadInConfig(); err != nil {
        return nil, err
    }
    var cfg Config
    if err := viper.Unmarshal(&cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}