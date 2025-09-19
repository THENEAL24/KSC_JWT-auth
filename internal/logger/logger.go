package logger

import "go.uber.org/zap"

func New() *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stdout"}
	logger, _ := cfg.Build()
	return logger
}
