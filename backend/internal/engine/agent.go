// Package engine 实现 engine-agent 的服务端（与 Suricata 同容器）与客户端（api/worker 调用）。
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Status 是引擎运行状态的只读视图。
type Status struct {
	Running     bool   `json:"running"`
	RuleLoadMs  int64  `json:"rule_load_ms"`
	RulesLoaded int64  `json:"rules_loaded"`
	KernelDrops int64  `json:"kernel_drops"`
	Version     string `json:"version"`
}

// AgentServer 是 engine-agent 的 HTTP 服务端，仅内部网络监听，靠共享 token 鉴权（M7）。
type AgentServer struct {
	token     string
	suriBin   string
	socketPat string
}

// NewAgentServer 构造 agent 服务端。
func NewAgentServer(token, suriBin, socketPath string) *AgentServer {
	return &AgentServer{token: token, suriBin: suriBin, socketPat: socketPath}
}

// Handler 返回挂载好的路由（标准库 mux，agent 镜像内不引 chi 也可以，这里统一用 chi 之外的最小依赖）。
func (a *AgentServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", a.auth(a.handleStatus))
	mux.HandleFunc("POST /v1/replay", a.auth(a.handleReplay))
	mux.HandleFunc("POST /v1/reload", a.auth(a.handleReload))
	mux.HandleFunc("POST /v1/validate-rules", a.auth(a.handleValidate))
	return mux
}

func (a *AgentServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Token") != a.token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *AgentServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	// 骨架期：只探测 socket 是否存在；真实计数器走 dump-counters（待验证，架构设计 §13）
	st := Status{}
	if _, err := net.Dial("unix", a.socketPat); err == nil {
		st.Running = true
	}
	writeJSON(w, http.StatusOK, st)
}

// replayRequest 只接受 id，不接受路径——路径由 agent 自行拼接（M7 路径穿越防护）。
type replayRequest struct {
	TaskID string `json:"task_id"`
	PcapID string `json:"pcap_id"`
}

func (a *AgentServer) handleReplay(w http.ResponseWriter, r *http.Request) {
	var req replayRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if !isUUID(req.TaskID) || !isUUID(req.PcapID) {
		http.Error(w, `{"error":"task_id/pcap_id must be UUID"}`, http.StatusBadRequest)
		return
	}
	// 骨架期占位：真实实现经 unix socket 发送 pcap-file 命令（命令名待验证）
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":  "not implemented in skeleton",
		"task":   req.TaskID,
		"pcap":   req.PcapID,
	})
}

func (a *AgentServer) handleReload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// suricata -T 校验当前规则目录（参数数组，绝不 sh -c；M7）
	cmd := exec.CommandContext(r.Context(), a.suriBin, "-T",
		"-c", "/etc/suricata/suricata.yaml",
		"-l", "/var/log/suricata")
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":  "suricata -T failed",
			"detail": strings.TrimSpace(string(out)),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "elapsed_ms": time.Since(start).Milliseconds()})
}

func (a *AgentServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	// 占位：真实实现把候选规则写入临时文件再 suricata -T；骨架期直接返回 501
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented in skeleton"})
}

func isUUID(s string) bool {
	if len(s) != 36 || strings.Count(s, "-") != 4 {
		return false
	}
	for _, c := range s {
		if c != '-' && !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Client 是 api/worker 调用 engine-agent 的客户端。
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient 构造 agent 客户端。
func NewClient(baseURL, token string) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Status 获取引擎状态。
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var st Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Reload 触发规则校验/重载。
func (c *Client) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/reload", nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Agent-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("agent %s %s: status %d", method, path, resp.StatusCode)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) {
			return fmt.Errorf("decode agent response: %w", err)
		}
	}
	return nil
}
