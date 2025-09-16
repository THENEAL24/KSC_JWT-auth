package logger

import "go.uber.org/zap"

// New returns a production zap logger configured to write to stdout.
func New() *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stdout"}
	logger, _ := cfg.Build()
	return logger
}
