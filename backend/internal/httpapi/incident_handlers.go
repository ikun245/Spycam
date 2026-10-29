package httpapi

import (
	"net/http"
	"strconv"

	"spycam/backend/internal/store/gen"
)

// handleListIncidents 攻击事件列表（S3）。
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	q := gen.New(s.pool)
	rows, err := q.ListIncidents(r.Context(), gen.ListIncidentsParams{Limit: limit, Offset: offset})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	total, err := q.CountIncidents(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []gen.Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": rows})
}

// handleGetIncident 事件详情：含阶段排序的告警组列表（攻击链视图）。
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	q := gen.New(s.pool)
	incident, err := q.GetIncident(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "incident not found")
		return
	}
	groups, err := q.ListIncidentGroups(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if groups == nil {
		groups = []gen.ListIncidentGroupsRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": incident, "groups": groups})
}
