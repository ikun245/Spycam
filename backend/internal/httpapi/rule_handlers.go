package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"spycam/backend/internal/rules"
	"spycam/backend/internal/store/gen"
)

// handleListRules 规则列表（M4 规则管理-查看）。
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rows, err := gen.New(s.pool).ListRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []gen.ListRulesRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

// handleGetRule 规则原文查看（架构设计 §6.3 GET /rules/{sid}，viewer+）。
func (s *Server) handleGetRule(w http.ResponseWriter, r *http.Request) {
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil || sid <= 0 {
		writeErr(w, http.StatusBadRequest, "bad sid")
		return
	}
	rule, err := gen.New(s.pool).GetRule(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// lastLine 取引擎输出的最后一行非空内容作为错误摘要，避免把整段日志回传给前端。
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return "unknown error"
}

// handleToggleRule 规则启停（M4：改完必须真的生效）。
// 流程：校验请求 → 更新 DB → 生成规则文件 → suricata -T 校验 → 失败回滚 → 热重载。
func (s *Server) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad sid")
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "body must be {\"enabled\":bool}")
		return
	}

	q := gen.New(s.pool)
	if _, err := q.GetRule(r.Context(), sid); err != nil {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}

	// 1. 更新数据库
	if err := q.SetRuleEnabled(r.Context(), gen.SetRuleEnabledParams{Sid: sid, Enabled: *req.Enabled}); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}

	// 2. 生成启用的规则文件（原子写）
	// 3. 热重载（agent 内部走 ruleset-reload-nonblocking）；失败则回滚 DB 与文件
	enabledRows, err := q.ListEnabledRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list enabled failed")
		return
	}
	if err := rules.GenerateActiveFile(s.cfg.RulesActiveDir, enabledRows); err != nil {
		writeErr(w, http.StatusInternalServerError, "generate rules file failed")
		return
	}
	if err := s.agent.Reload(r.Context()); err != nil {
		// 回滚数据库与文件，保证一致
		_ = q.SetRuleEnabled(r.Context(), gen.SetRuleEnabledParams{Sid: sid, Enabled: !*req.Enabled})
		if rows2, lerr := q.ListEnabledRules(r.Context()); lerr == nil {
			_ = rules.GenerateActiveFile(s.cfg.RulesActiveDir, rows2)
		}
		slog.Warn("rule reload failed, rolled back", "sid", sid, "err", err)
		s.audit(r.Context(), actor(r), auditRuleToggle, strconv.FormatInt(sid, 10),
			map[string]any{"enabled": *req.Enabled, "result": "rolled_back", "error": err.Error()})
		writeErr(w, http.StatusBadGateway, "reload failed, change rolled back")
		return
	}

	version := s.recordRuleRevision(r.Context(), actor(r), map[string]any{"op": "toggle", "sid": sid, "enabled": *req.Enabled})
	s.audit(r.Context(), actor(r), auditRuleToggle, strconv.FormatInt(sid, 10),
		map[string]any{"enabled": *req.Enabled, "result": "applied", "ruleset_version": version})
	writeJSON(w, http.StatusOK, map[string]any{"sid": sid, "enabled": *req.Enabled, "reloaded": true, "ruleset_version": version})
}

// handleGetAlertRaw 返回告警原始 JSON 与规则原文（M4 详情）。
func (s *Server) handleGetAlertRaw(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	q := gen.New(s.pool)
	alert, err := q.GetAlert(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "alert not found")
		return
	}
	resp := map[string]any{
		"alert": alert,
		"raw":   json.RawMessage(alert.Raw),
	}
	if rule, rerr := q.GetRule(r.Context(), alert.Sid); rerr == nil {
		resp["rule_raw"] = rule.Raw
		resp["rule_stage"] = rule.Stage
		resp["rule_mitre_tactic"] = rule.MitreTactic
		resp["rule_mitre_technique"] = rule.MitreTechnique
	}
	if alert.FlowID.Valid {
		if flow, ferr := q.GetFlow(r.Context(), gen.GetFlowParams{TaskID: alert.TaskID, FlowID: alert.FlowID.Int64}); ferr == nil {
			resp["flow"] = flow
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
