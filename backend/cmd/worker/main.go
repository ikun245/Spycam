package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/config"
)

// worker 负责回放调度、eve.json 采集归一化、聚合与事件串联（架构设计 §6.4）。
// 骨架期：完成配置加载与 PG/Redis 连接，消费逻辑在数据层落地后补充。
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("pg connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("redis ping", "err", err)
		os.Exit(1)
	}

	slog.Info("worker started",
		"agg_window_seconds", cfg.AggWindowSeconds,
		"eve_out_dir", os.Getenv("EVE_OUT_DIR"))

	<-ctx.Done()
	slog.Info("worker stopped")
}
