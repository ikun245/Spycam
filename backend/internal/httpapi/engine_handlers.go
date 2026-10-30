package httpapi

import (
	"net/http"

	"spycam/backend/internal/ingest"
	"spycam/backend/internal/store/gen"
)

// handleEngineStatusV2 引擎可观测（S6）：agent 存活状态 + 回放/实时两个引擎实例各自最近一条 engine_stats
// （规则加载耗时、内核丢包、告警计数）。
func (s *Server) handleEngineStatusV2(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{}
	if st, err := s.agent.Status(r.Context()); err == nil {
		resp["agent"] = st
	} else {
		resp["agent"] = map[string]any{"running": false}
	}
	q := gen.New(s.pool)
	if stat, err := q.LatestEngineStat(r.Context(), ingest.SourceReplay); err == nil {
		resp["latest_stats"] = stat
	}
	// 实时抓包实例（live profile）独立上报；未启用时不返回该字段
	if stat, err := q.LatestEngineStat(r.Context(), ingest.SourceLive); err == nil {
		resp["live_stats"] = stat
	}
	writeJSON(w, http.StatusOK, resp)
}
