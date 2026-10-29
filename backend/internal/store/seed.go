package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	sidRe = regexp.MustCompile(`\bsid:(\d+)\b`)
	msgRe = regexp.MustCompile(`\bmsg:"([^"]*)"\b`)
)

// SeedRules 将种子规则目录下的 *.rules 导入 rules 表（幂等，ON CONFLICT 跳过）。
func SeedRules(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read seed rules dir %s: %w", dir, err)
	}
	var imported int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".rules" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		n, err := importRuleLines(ctx, pool, string(data))
		if err != nil {
			return fmt.Errorf("import %s: %w", path, err)
		}
		imported += n
		slog.Info("seed rules file processed", "file", e.Name(), "rules", n)
	}
	slog.Info("seed rules done", "total", imported)
	return nil
}

func importRuleLines(ctx context.Context, pool *pgxpool.Pool, content string) (int, error) {
	var count int
	for _, line := range splitLines(content) {
		m := sidRe.FindStringSubmatch(line)
		if m == nil {
			continue // 空行或注释
		}
		var sid int64
		if _, err := fmt.Sscanf(m[1], "%d", &sid); err != nil {
			return count, fmt.Errorf("bad sid %q: %w", m[1], err)
		}
		msg := ""
		if mm := msgRe.FindStringSubmatch(line); mm != nil {
			msg = mm[1]
		}
		tag, err := pool.Exec(ctx,
			`INSERT INTO rules (sid, raw, msg, enabled, source)
			 VALUES ($1, $2, $3, TRUE, 'seed')
			 ON CONFLICT (sid) DO NOTHING`,
			sid, line, msg)
		if err != nil {
			return count, fmt.Errorf("insert rule sid=%d: %w", sid, err)
		}
		if tag.RowsAffected() > 0 {
			count++
		}
	}
	return count, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, trimCR(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimCR(s[start:]))
	return out
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}
