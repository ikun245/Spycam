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

	// 离线回放时告警 ts 是 pcap 内原始时间（可能远早于当前），
	// 因此时间过滤可选：传 since（unix 秒）则过滤，不传则统计全部。
	var since pgtype.Timestamptz
	if v, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64); err == nil && v > 0 {
		since = pgtype.Timestamptz{Time: time.Unix(v, 0), Valid: true}
	}

	total, _ := q.CountAllAlerts(r.Context())
	trend, _ := q.TrendByHour(r.Context(), since)
	topSrc, _ := q.TopSrcIPs(r.Context(), gen.TopSrcIPsParams{Since: since, Limit: 10})
	topSigs, _ := q.TopSignatures(r.Context(), gen.TopSignaturesParams{Since: since, Limit: 10})
	topPorts, _ := q.TopDestPorts(r.Context(), gen.TopDestPortsParams{Since: since, Limit: 10})
	severityDist, _ := q.SeverityDistribution(r.Context())
	stageDist, _ := q.StageDistribution(r.Context())
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
	if severityDist == nil {
		severityDist = []gen.SeverityDistributionRow{}
	}
	if stageDist == nil {
		stageDist = []gen.StageDistributionRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_alerts":          total,
		"pending_groups":        pending,
		"rules_total":           rulesTotal,
		"rules_enabled":         rulesEnabled,
		"trend_by_hour":         trend,
		"top_src_ips":           topSrc,
		"top_signatures":        topSigs,
		"top_dest_ports":        topPorts,
		"severity_distribution": severityDist,
		"stage_distribution":    stageDist,
	})
}
