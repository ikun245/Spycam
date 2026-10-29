package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"

	"spycam/backend/internal/auth"
	"spycam/backend/internal/store/gen"
)

// 审计动作（audit_log.action）
const (
	auditLoginOK     = "login.success"
	auditLoginFail   = "login.failure"
	auditLoginLocked = "login.locked"
	auditLogout      = "logout"
	auditRuleToggle  = "rule.toggle"
	auditRuleCreate  = "rule.create"
	auditGroupTriage = "group.triage"
	auditPcapUpload  = "pcap.upload"
	auditTaskCreate  = "task.create"
	auditPcapExport  = "pcap.export"
)

// audit 写审计日志。审计是旁路记录：失败只打日志，不阻断业务主流程。
func (s *Server) audit(ctx context.Context, username, action, target string, detail map[string]any) {
	var raw []byte
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			slog.Warn("audit marshal", "action", action, "err", err)
		} else {
			raw = b
		}
	}
	if err := gen.New(s.pool).InsertAudit(ctx, gen.InsertAuditParams{
		Username: username,
		Action:   action,
		Target:   pgtype.Text{String: target, Valid: target != ""},
		Detail:   raw,
	}); err != nil {
		slog.Warn("audit write failed", "action", action, "target", target, "err", err)
	}
}

// actor 取当前登录用户名（中间件保证已认证；兜底返回空串，actor_id 落 NULL）。
func actor(r *http.Request) string {
	if id, ok := auth.FromContext(r.Context()); ok {
		return id.Username
	}
	return ""
}

// recordRuleRevision 规则集成功生效后写入版本快照，返回新版本号（失败返回 0 并记日志）。
func (s *Server) recordRuleRevision(ctx context.Context, username string, change map[string]any) int64 {
	b, err := json.Marshal(change)
	if err != nil {
		slog.Warn("rule revision marshal", "err", err)
		return 0
	}
	v, err := gen.New(s.pool).CreateRuleRevision(ctx, gen.CreateRuleRevisionParams{Change: b, Username: username})
	if err != nil {
		slog.Warn("rule revision write failed", "err", err)
		return 0
	}
	return v
}

type auditItem struct {
	ID        int64              `json:"id"`
	Username  string             `json:"username"`
	Action    string             `json:"action"`
	Target    pgtype.Text        `json:"target"`
	Detail    json.RawMessage    `json:"detail"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
}

// handleListAudit 审计日志（admin）：最近 N 条，默认 100，上限 500。
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := int32(100)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, http.StatusBadRequest, "limit must be 1..500")
			return
		}
		limit = int32(n)
	}
	rows, err := gen.New(s.pool).ListAuditLog(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	items := make([]auditItem, 0, len(rows))
	for _, row := range rows {
		it := auditItem{ID: row.ID, Username: row.Username, Action: row.Action, Target: row.Target, CreatedAt: row.CreatedAt}
		// jsonb 以 []byte 扫出，直接作为原始 JSON 输出，避免被编码成 base64
		if len(row.Detail) > 0 {
			it.Detail = json.RawMessage(row.Detail)
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
