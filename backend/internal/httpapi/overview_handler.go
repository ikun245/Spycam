package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"spycam/backend/internal/store/gen"
)

// handleOverview 总览统计（M4：时间趋势 + Top 源 IP / 签名 / 目的端口 + 待处置数）。
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	q := gen.New(s.pool)
	hours := 24
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v > 0 && v <= 168 {
		hours = v
	}
	since := pgtype.Timestamptz{Time: time.Now().Add(-time.Duration(hours) * time.Hour), Valid: true}

	total, _ := q.CountAllAlerts(r.Context())
	trend, _ := q.TrendByHour(r.Context(), since)
	topSrc, _ := q.TopSrcIPs(r.Context(), gen.TopSrcIPsParams{Ts: since, Limit: 10})
	topSigs, _ := q.TopSignatures(r.Context(), gen.TopSignaturesParams{Ts: since, Limit: 10})
	topPorts, _ := q.TopDestPorts(r.Context(), gen.TopDestPortsParams{Ts: since, Limit: 10})
	pending, _ := q.CountPendingGroups(r.Context())
	rulesTotal, _ := q.CountRules(r.Context())
	rulesEnabled, _ := q.CountEnabledRules(r.Context())

	if trend == nil {
		trend = []gen.TrendByHourRow{}
	}
	if topSrc == nil {
		topSrc = []gen.TopSrcIPsRow{}
	}
	if topSigs == nil {
		topSigs = []gen.TopSignaturesRow{}
	}
	if topPorts == nil {
		topPorts = []gen.TopDestPortsRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_alerts":   total,
		"pending_groups": pending,
		"rules_total":    rulesTotal,
		"rules_enabled":  rulesEnabled,
		"trend_by_hour":  trend,
		"top_src_ips":    topSrc,
		"top_signatures": topSigs,
		"top_dest_ports": topPorts,
	})
}
