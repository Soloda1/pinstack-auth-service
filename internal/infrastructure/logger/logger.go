package logger

import (
	"log/slog"
	"os"
	ports "pinstack-auth-service/internal/domain/ports/output"
)

const (
	envDev  = "dev"
	envProd = "prod"
)

type Logger struct {
	*slog.Logger
}

func New(env string) *Logger {
	var log *slog.Logger
	switch env {
	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}))
	default:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}))
	}

	return &Logger{log}
}

func (l *Logger) With(args ...slog.Attr) ports.Logger {
	// Convert []slog.Attr to []any for slog.Logger.With
	anyArgs := make([]any, 0, len(args))
	for i := range args {
		anyArgs = append(anyArgs, args[i])
	}
	return &Logger{l.Logger.With(anyArgs...)}
}
