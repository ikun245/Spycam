package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"

	"spycam/backend/internal/auth"
	"spycam/backend/internal/store/gen"
)

var validGroupStatus = map[string]bool{
	"new": true, "confirmed": true, "false_positive": true, "ignored": true,
}

// handleListGroups 聚合告警组列表（S1/S2）。
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	params := gen.ListGroupsParams{Limit: limit, Offset: offset}
	if st := r.URL.Query().Get("status"); st != "" {
		if !validGroupStatus[st] {
			writeErr(w, http.StatusBadRequest, "invalid status")
			return
		}
		params.Status = pgtype.Text{String: st, Valid: true}
	}
	q := gen.New(s.pool)
	rows, err := q.ListGroups(r.Context(), params)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	total, err := q.CountGroups(r.Context(), params.Status)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []gen.ListGroupsRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": rows})
}

// handleTriageGroup 处置流转（S2）：new → confirmed/false_positive/ignored，写审计。
func (s *Server) handleTriageGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if !validGroupStatus[req.Status] {
		writeErr(w, http.StatusBadRequest, "status must be new|confirmed|false_positive|ignored")
		return
	}
	identity, ok := auth.FromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	q := gen.New(s.pool)
	old, err := q.GetGroup(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "group not found")
		return
	}

	var assignee pgtype.Int8
	if u, uerr := q.GetUserByUsername(r.Context(), identity.Username); uerr == nil {
		assignee = pgtype.Int8{Int64: u.ID, Valid: true}
	}
	if err := q.SetGroupStatus(r.Context(), gen.SetGroupStatusParams{
		ID: id, Status: req.Status, Assignee: assignee,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	var actorID pgtype.Int8
	if assignee.Valid {
		actorID = assignee
	}
	if err := q.InsertTriageAction(r.Context(), gen.InsertTriageActionParams{
		GroupID:    id,
		FromStatus: old.Status,
		ToStatus:   req.Status,
		ActorID:    actorID,
		Note:       pgtype.Text{String: req.Note, Valid: req.Note != ""},
	}); err != nil {
		// 审计失败不阻断主流程，但记录日志
		slog.Warn("triage audit write failed", "group_id", id, "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": req.Status})
}
