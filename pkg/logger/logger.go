package logger

import (
	"go.uber.org/zap"
)

type Config struct {
	Level            string
	Encoding         string
	OutputPaths      []string
	ErrorOutputPaths []string
}

func New() *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	logger, err := cfg.Build()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	return logger
}

func NewWithConfig(config Config) *zap.Logger {
	var zapConfig zap.Config

	switch config.Encoding {
	case "console":
		zapConfig = zap.NewDevelopmentConfig()
	default:
		zapConfig = zap.NewProductionConfig()
	}

	level := zap.InfoLevel
	switch config.Level {
	case "debug":
		level = zap.DebugLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	if len(config.OutputPaths) > 0 {
		zapConfig.OutputPaths = config.OutputPaths
	}
	if len(config.ErrorOutputPaths) > 0 {
		zapConfig.ErrorOutputPaths = config.ErrorOutputPaths
	}

	logger, err := zapConfig.Build()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}

	return logger
}
