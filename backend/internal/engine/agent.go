// Package engine 实现 engine-agent 的服务端（与 Suricata 同容器）与客户端（api/worker 调用）。
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// suricataConfig 在镜像内的路径；不放 /etc/suricata（基础镜像把它声明为 VOLUME，重建容器不会更新）。
const suricataConfig = "/opt/spycam/suricata.yaml"

// Status 是引擎运行状态的只读视图。未测得的字段省略（omitempty），避免前端把“未知”显示成 0。
type Status struct {
	Running     bool   `json:"running"`
	RuleLoadMs  int64  `json:"rule_load_ms,omitempty"`
	RulesLoaded int64  `json:"rules_loaded,omitempty"`
	KernelDrops int64  `json:"kernel_drops,omitempty"`
	Version     string `json:"version,omitempty"`
}

// AgentServer 是 engine-agent 的 HTTP 服务端，仅内部网络监听，靠共享 token 鉴权（M7）。
type AgentServer struct {
	token     string
	suriBin   string
	socketPat string
	// lastReloadMs 最近一次「suricata -T 校验 + 热重载」耗时；0 表示自 agent 启动后未重载过
	lastReloadMs atomic.Int64
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
	mux.HandleFunc("GET /v1/replay-status", a.auth(a.handleReplayStatus))
	mux.HandleFunc("POST /v1/reload", a.auth(a.handleReload))
	mux.HandleFunc("POST /v1/validate-rules", a.auth(a.handleValidate))
	return mux
}

// handleReplayStatus 转发 pcap-current / pcap-file-number，
// worker 据此判断回放是否完成（Suricata 按任务串行处理）。
func (a *AgentServer) handleReplayStatus(w http.ResponseWriter, r *http.Request) {
	cmd := NewSuricataCmd(a.socketPat, 10*time.Second)
	out := map[string]any{}
	for name, key := range map[string]string{
		"pcap-current":     "current",
		"pcap-file-number": "queued",
	} {
		msg, err := cmd.Do(r.Context(), name, nil)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		out[key] = msg
	}
	writeJSON(w, http.StatusOK, out)
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
	// Close immediately: an idle client can block Suricata's command socket.
	st := Status{RuleLoadMs: a.lastReloadMs.Load()}
	conn, err := net.DialTimeout("unix", a.socketPat, time.Second)
	if err == nil {
		_ = conn.Close()
		st.Running = true
	}
	writeJSON(w, http.StatusOK, st)
}

// replayRequest 只接受 id，不接受路径——路径由 agent 自行拼接（M7 路径穿越防护）。
type replayRequest struct {
	TaskID string `json:"task_id"`
	PcapID string `json:"pcap_id"`
}

// handleReplay 经 unix socket 提交 pcap-file 命令：引擎在同一容器内读 pcaps 卷，
// 输出写到按任务隔离的目录 eve-out/tasks/<task_id>/（架构设计 §3.1）。
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
	pcapPath := "/data/pcaps/" + req.PcapID + ".pcap"
	outDir := "/var/log/suricata/tasks/" + req.TaskID
	// Suricata pcap-file 要求输出目录必须已存在
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create output dir: " + err.Error()})
		return
	}

	cmd := NewSuricataCmd(a.socketPat, 60*time.Second)
	msg, err := cmd.Do(r.Context(), "pcap-file", map[string]string{
		"filename":   pcapPath,
		"output-dir": outDir,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"task_id": req.TaskID, "output_dir": outDir, "engine": msg})
}

func (a *AgentServer) handleReload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// 先校验规则（参数数组，绝不 sh -c；M7）
	cmd := exec.CommandContext(r.Context(), a.suriBin, "-T",
		"-c", suricataConfig,
		"-l", "/var/log/suricata")
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":  "suricata -T failed",
			"detail": strings.TrimSpace(string(out)),
		})
		return
	}
	// 热重载：非阻塞 reload，引擎平滑加载新规则集
	sock := NewSuricataCmd(a.socketPat, 30*time.Second)
	if _, err := sock.Do(r.Context(), "ruleset-reload-nonblocking", nil); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":      "ruleset reload failed",
			"detail":     err.Error(),
			"validated":  true,
			"elapsed_ms": time.Since(start).Milliseconds(),
		})
		return
	}
	elapsed := time.Since(start).Milliseconds()
	a.lastReloadMs.Store(max(elapsed, 1))
	writeJSON(w, http.StatusOK, map[string]any{
		"validated":  true,
		"reloaded":   true,
		"elapsed_ms": elapsed,
	})
}

// maxValidateBytes 候选规则文本上限，防止超大请求拖垮校验进程。
const maxValidateBytes = 256 << 10

// handleValidate 把候选规则写入临时文件，用 `suricata -T -S <file>` 只校验该文件（不影响运行中的规则集）。
func (a *AgentServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules string `json:"rules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxValidateBytes+1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"rules\":string}"})
		return
	}
	if strings.TrimSpace(req.Rules) == "" || len(req.Rules) > maxValidateBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rules must be non-empty and <= 256KiB"})
		return
	}
	dir, err := os.MkdirTemp("", "spycam-validate-")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create temp dir failed"})
		return
	}
	defer os.RemoveAll(dir)
	ruleFile := dir + "/candidate.rules"
	if err := os.WriteFile(ruleFile, []byte(req.Rules), 0o600); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write temp rules failed"})
		return
	}
	start := time.Now()
	cmd := exec.CommandContext(r.Context(), a.suriBin, "-T",
		"-c", suricataConfig,
		"-S", ruleFile,
		"-l", dir)
	out, err := cmd.CombinedOutput()
	resp := map[string]any{"valid": err == nil, "elapsed_ms": time.Since(start).Milliseconds()}
	if err != nil {
		resp["detail"] = strings.ReplaceAll(strings.TrimSpace(string(out)), dir+"/", "")
	}
	writeJSON(w, http.StatusOK, resp)
}

// ValidateRules 调用 agent 对候选规则做 suricata -T 校验；返回 (是否通过, 失败详情)。
func (c *Client) ValidateRules(ctx context.Context, rulesText string) (bool, string, error) {
	buf, err := json.Marshal(map[string]string{"rules": rulesText})
	if err != nil {
		return false, "", err
	}
	var out struct {
		Valid  bool   `json:"valid"`
		Detail string `json:"detail"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/validate-rules", bytes.NewReader(buf), &out); err != nil {
		return false, "", err
	}
	return out.Valid, out.Detail, nil
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

// Replay 提交回放任务。
func (c *Client) Replay(ctx context.Context, taskID, pcapID string) (map[string]any, error) {
	var out map[string]any
	body := map[string]string{"task_id": taskID, "pcap_id": pcapID}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if err := c.do(ctx, http.MethodPost, "/v1/replay", bytes.NewReader(buf), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReplayStatus 查询引擎回放进度（pcap-current 等）。
func (c *Client) ReplayStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/v1/replay-status", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
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
