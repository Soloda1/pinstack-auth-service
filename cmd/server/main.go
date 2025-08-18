package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	token_service "pinstack-auth-service/internal/application/service"
	"pinstack-auth-service/internal/infrastructure/config"
	delivery_grpc "pinstack-auth-service/internal/infrastructure/inbound/grpc"
	auth_grpc "pinstack-auth-service/internal/infrastructure/inbound/grpc/auth"
	metrics_server "pinstack-auth-service/internal/infrastructure/inbound/metrics"
	infraLogger "pinstack-auth-service/internal/infrastructure/logger"
	authManager "pinstack-auth-service/internal/infrastructure/outbound/auth"
	user "pinstack-auth-service/internal/infrastructure/outbound/client/user"

	prometheus_metrics "pinstack-auth-service/internal/infrastructure/outbound/metrics/prometheus"
	token_repository "pinstack-auth-service/internal/infrastructure/outbound/repository/postgres"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	cfg := config.MustLoad()
	dsn := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.Database.Username,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DbName)
	ctx := context.Background()
	log := infraLogger.New(cfg.Env)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Error("Failed to parse postgres poolConfig", slog.String("error", err.Error()))
		os.Exit(1)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Error("Failed to create postgres pool", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	userServiceConn, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", cfg.UserService.Address, cfg.UserService.Port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Error("Failed to connect to user service", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() {
		if err := userServiceConn.Close(); err != nil {
			log.Error("Failed to close User Service connection", slog.String("error", err.Error()))
		}
	}()

	userClient := user.NewUserClient(userServiceConn, log)
	tokenManager := authManager.NewTokenManager(cfg.JWT.Secret, cfg.JWT.Secret, cfg.JWT.AccessExpiresAt, cfg.JWT.RefreshExpiresAt, log)

	metricsProvider := prometheus_metrics.NewPrometheusMetricsProvider()

	tokenRepo := token_repository.NewTokenRepository(pool, log, metricsProvider)
	tokenService := token_service.NewService(tokenRepo, tokenManager, userClient, log, metricsProvider)

	authGRPCApi := auth_grpc.NewAuthGRPCService(tokenService, log)
	grpcServer := delivery_grpc.NewServer(authGRPCApi, cfg.GRPCServer.Address, cfg.GRPCServer.Port, log, metricsProvider)

	metricsServer := metrics_server.NewMetricsServer(cfg.Prometheus.Address, cfg.Prometheus.Port, log)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	done := make(chan bool, 1)
	metricsDone := make(chan bool, 1)

	go func() {
		if err := grpcServer.Run(); err != nil {
			log.Error("gRPC server error", slog.String("error", err.Error()))
		}
		done <- true
	}()

	go func() {
		if err := metricsServer.Run(); err != nil {
			log.Error("Metrics server error", slog.String("error", err.Error()))
		}
		metricsDone <- true
	}()

	<-quit
	log.Info("Shutting down servers...")

	metricsProvider.SetServiceHealth(false)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := grpcServer.Shutdown(); err != nil {
		log.Error("gRPC server shutdown error", slog.String("error", err.Error()))
	}

	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		log.Error("Metrics server shutdown error", slog.String("error", err.Error()))
	}

	<-done
	<-metricsDone

	log.Info("Server exited")
}
