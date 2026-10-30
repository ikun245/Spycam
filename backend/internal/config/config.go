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
	// CookieSecure 为 true 时会话 Cookie 带 Secure（HTTPS 反代前部署时开启；本地 http://127.0.0.1 需关闭）
	CookieSecure bool
	// LiveIface 实时抓包网卡（与 suricata-live 共用 LIVE_IFACE），仅用于前端展示接入状态
	LiveIface string
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
		LiveIface:         os.Getenv("LIVE_IFACE"),
	}

	for name, v := range map[string]string{
		"DATABASE_URL":        c.DatabaseURL,
		"ENGINE_AGENT_TOKEN":  c.EngineAgentToken,
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

	secure, err := strconv.ParseBool(getEnv("COOKIE_SECURE", "false"))
	if err != nil {
		return nil, fmt.Errorf("%w: COOKIE_SECURE must be true/false", ErrInvalidConfig)
	}
	c.CookieSecure = secure

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
