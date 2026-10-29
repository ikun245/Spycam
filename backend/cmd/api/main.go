package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/auth"
	"spycam/backend/internal/config"
	"spycam/backend/internal/engine"
	"spycam/backend/internal/httpapi"
	"spycam/backend/internal/observability"
	"spycam/backend/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// PostgreSQL 连接池
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("pg connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Redis
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("redis ping", "err", err)
		os.Exit(1)
	}

	// 迁移 + 种子数据（幂等）
	if err := store.Migrate(ctx, cfg.DatabaseURL, cfg.MigrationsDir); err != nil {
		slog.Error("migrate", "err", err)
		os.Exit(1)
	}
	if err := auth.SeedAdmin(ctx, pool, cfg.SeedAdminUser, cfg.SeedAdminPassword); err != nil {
		slog.Error("seed admin", "err", err)
		os.Exit(1)
	}
	if cfg.SeedRulesDir != "" {
		if err := store.SeedRules(ctx, pool, cfg.SeedRulesDir); err != nil {
			slog.Error("seed rules", "err", err)
			os.Exit(1)
		}
	}

	// 依赖探针
	checks := map[string]observability.Check{
		"postgres": func(ctx context.Context) error { return pool.Ping(ctx) },
		"redis":    func(ctx context.Context) error { return rdb.Ping(ctx).Err() },
		"agent": func(ctx context.Context) error {
			_, err := engine.NewClient(cfg.EngineAgentURL, cfg.EngineAgentToken).Status(ctx)
			return err
		},
	}

	agent := engine.NewClient(cfg.EngineAgentURL, cfg.EngineAgentToken)
	srv := httpapi.NewServer(cfg, auth.NewService(pool, rdb, cfg.SessionTTL), agent,
		observability.HealthzHandler, observability.ReadyHandler(checks))

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("api listening", "addr", cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
