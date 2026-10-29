package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	sidRe    = regexp.MustCompile(`\bsid:(\d+)\b`)
	msgRe    = regexp.MustCompile(`\bmsg:\s*"([^"]*)"`)
	classRe  = regexp.MustCompile(`\bclasstype:\s*([\w-]+)`)
	sevRe    = regexp.MustCompile(`\bseverity:\s*(\d+)`)
	stageRe  = regexp.MustCompile(`\bstage\s+(\w+)`)
	tacticRe = regexp.MustCompile(`\bmitre_tactic\s+([^,;]+)`)
	techRe   = regexp.MustCompile(`\bmitre_technique\s+([^,;]+)`)
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
		msg := firstMatch(msgRe, line)
		classtype := firstMatch(classRe, line)
		severity := pgtype.Int4{}
		if sm := sevRe.FindStringSubmatch(line); sm != nil {
			var sv int
			if _, err := fmt.Sscanf(sm[1], "%d", &sv); err == nil {
				severity = pgtype.Int4{Int32: int32(sv), Valid: true}
			}
		}
		stage := firstMatch(stageRe, line)
		tactic := strings.TrimSpace(firstMatch(tacticRe, line))
		technique := strings.TrimSpace(firstMatch(techRe, line))

		tag, err := pool.Exec(ctx,
			`INSERT INTO rules (sid, raw, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source)
			 VALUES ($1, $2, $3, TRUE, $4, $5, $6, $7, $8, 'seed')
			 ON CONFLICT (sid) DO UPDATE SET
			   raw = EXCLUDED.raw, msg = EXCLUDED.msg, classtype = EXCLUDED.classtype,
			   severity = EXCLUDED.severity, stage = EXCLUDED.stage,
			   mitre_tactic = EXCLUDED.mitre_tactic, mitre_technique = EXCLUDED.mitre_technique`,
			sid, line, msg, strPtr(classtype), severity, strPtr(stage), strPtr(tactic), strPtr(technique))
		if err != nil {
			return count, fmt.Errorf("insert rule sid=%d: %w", sid, err)
		}
		if tag.RowsAffected() > 0 {
			count++
		}
	}
	return count, nil
}

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil && len(m) > 1 {
		return m[1]
	}
	return ""
}

func strPtr(s string) any {
	if s == "" {
		return nil
	}
	return s
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
