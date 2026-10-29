package store

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Migrate 使用 goose 执行 migrations 目录下的全部迁移，启动时自动调用（M6）。
func Migrate(ctx context.Context, databaseURL, dir string) error {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	sqldb := stdlib.OpenDB(*cfg)
	defer sqldb.Close()

	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("migrations dir %s: %w", dir, err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, os.DirFS(dir))
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
