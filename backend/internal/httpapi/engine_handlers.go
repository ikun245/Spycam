package httpapi

import (
	"net/http"

	"spycam/backend/internal/store/gen"
)

// handleEngineStatusV2 引擎可观测（S6）：agent 存活状态 + 最近一条 engine_stats
// （规则加载耗时、内核丢包、告警计数）。
func (s *Server) handleEngineStatusV2(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{}
	if st, err := s.agent.Status(r.Context()); err == nil {
		resp["agent"] = st
	} else {
		resp["agent"] = map[string]any{"running": false}
	}
	if stat, err := gen.New(s.pool).LatestEngineStat(r.Context()); err == nil {
		resp["latest_stats"] = stat
	}
	writeJSON(w, http.StatusOK, resp)
}
