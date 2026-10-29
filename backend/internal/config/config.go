package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config 汇总全部运行时配置；只从环境变量读取（M7：密钥不入库不入 Git）。
type Config struct {
	DatabaseURL       string
	RedisAddr         string
	Listen            string
	SessionTTL        time.Duration
	MigrationsDir     string
	SeedRulesDir      string
	RulesActiveDir    string
	PcapsDir          string
	EngineAgentURL    string
	EngineAgentToken  string
	SeedAdminUser     string
	SeedAdminPassword string
	AggWindowSeconds  int
}

// Load 读取环境变量并校验必填项，缺失即返回错误（fail fast）。
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RedisAddr:         getEnv("REDIS_ADDR", "redis:6379"),
		Listen:            getEnv("API_LISTEN", ":8081"),
		MigrationsDir:     getEnv("MIGRATIONS_DIR", "/app/migrations"),
		SeedRulesDir:      getEnv("SEED_RULES_DIR", "/app/seed-rules"),
		RulesActiveDir:    getEnv("RULES_ACTIVE_DIR", "/rules-active"),
		PcapsDir:          getEnv("PCAPS_DIR", "/data/pcaps"),
		EngineAgentURL:    getEnv("ENGINE_AGENT_URL", "http://suricata:9090"),
		EngineAgentToken:  os.Getenv("ENGINE_AGENT_TOKEN"),
		SeedAdminUser:     getEnv("SEED_ADMIN_USER", "admin"),
		SeedAdminPassword: os.Getenv("SEED_ADMIN_PASSWORD"),
	}

	for name, v := range map[string]string{
		"DATABASE_URL":       c.DatabaseURL,
		"ENGINE_AGENT_TOKEN": c.EngineAgentToken,
		"SEED_ADMIN_PASSWORD": c.SeedAdminPassword,
	} {
		if v == "" {
			return nil, fmt.Errorf("%w: missing required env %s", ErrInvalidConfig, name)
		}
	}

	ttl, err := time.ParseDuration(getEnv("SESSION_TTL", "12h"))
	if err != nil {
		return nil, fmt.Errorf("%w: SESSION_TTL: %v", ErrInvalidConfig, err)
	}
	c.SessionTTL = ttl

	agg, err := strconv.Atoi(getEnv("AGG_WINDOW_SECONDS", "60"))
	if err != nil || agg <= 0 {
		return nil, fmt.Errorf("%w: AGG_WINDOW_SECONDS must be positive int", ErrInvalidConfig)
	}
	c.AggWindowSeconds = agg

	return c, nil
}

// ErrInvalidConfig 标识配置缺失或非法。
var ErrInvalidConfig = errors.New("invalid config")

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
