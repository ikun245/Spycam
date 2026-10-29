package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"spycam/backend/internal/engine"
)

// engine-agent 与 Suricata 同容器运行：监督引擎进程，提供受限内部控制接口（架构设计 §3.2）。
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	listen := flag.String("listen", ":9090", "内部 HTTP 监听地址")
	token := flag.String("token", "", "共享鉴权 token（必须来自环境变量）")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("ENGINE_AGENT_TOKEN")
	}
	if *token == "" {
		slog.Error("ENGINE_AGENT_TOKEN is required")
		os.Exit(1)
	}

	agent := engine.NewAgentServer(*token, "suricata", "/var/run/suricata.socket")
	slog.Info("engine-agent listening", "addr", *listen)
	if err := http.ListenAndServe(*listen, agent.Handler()); err != nil {
		slog.Error("agent server", "err", err)
		os.Exit(1)
	}
}
