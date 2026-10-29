// Package incident 实现 S3 攻击事件串联：同一源 IP 的告警组按时间临近归入同一事件，
// 阶段顺序来自规则 metadata（recon→bruteforce→exploit→c2→exfil），支撑攻击链视图与 C3。
package incident

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"spycam/backend/internal/store/gen"
)

// stageOrder 定义攻击链阶段顺序（值越小越靠前）。
var stageOrder = map[string]int{
	"recon":      1,
	"bruteforce": 2,
	"exploit":    3,
	"c2":         4,
	"exfil":      5,
}

// gap 是归入同一事件的最大告警间隔；超过则视为独立事件（可按需改为环境变量）。
const gap = 15 * time.Minute

// severityRank 用于取事件内最高严重级（数值越小越严重）；未知返回 99。
func severityRank(v any) int32 {
	if s, ok := v.(int32); ok {
		return s
	}
	return 99
}

// ChainTask 把指定任务的告警组按源 IP + 时间窗串联成攻击事件。幂等：
// 通过 incident_alerts 关联去重，重复调用只补新组。
func ChainTask(ctx context.Context, pool *pgxpool.Pool, taskID string) (int, error) {
	q := gen.New(pool)
	groups, err := q.ListGroupsForChain(ctx, taskID)
	if err != nil {
		return 0, fmt.Errorf("list groups: %w", err)
	}

	// 按源 IP 聚拢，组内按 first_seen 排序
	bySrc := map[string][]gen.ListGroupsForChainRow{}
	for _, g := range groups {
		bySrc[g.SrcIp] = append(bySrc[g.SrcIp], g)
	}

	chained := 0
	for srcIP, gs := range bySrc {
		sort.Slice(gs, func(i, j int) bool {
			return gs[i].FirstSeen.Time.Before(gs[j].FirstSeen.Time)
		})

		var incidentID int64
		var spanEnd time.Time
		var stages []string
		minSev := int32(99)

		flush := func() {
			if incidentID == 0 {
				return
			}
			summary := stageSummary(stages)
			if err := q.UpdateIncidentSpan(ctx, gen.UpdateIncidentSpanParams{
				ID:           incidentID,
				EndTs:        pgtype.Timestamptz{Time: spanEnd, Valid: true},
				StageSummary: pgtype.Text{String: summary, Valid: summary != ""},
				Severity:     sevPtr(minSev),
			}); err != nil {
				slog.Warn("incident span update", "err", err)
			}
			chained++
			incidentID = 0
			stages = stages[:0]
			minSev = 99
		}

		for _, g := range gs {
			startNew := incidentID == 0 ||
				g.FirstSeen.Time.Sub(spanEnd) > gap

			if startNew {
				flush()
				created, err := q.UpsertIncident(ctx, gen.UpsertIncidentParams{
					SrcIp:    srcIP,
					StartTs:  g.FirstSeen,
					EndTs:    g.LastSeen,
					Severity: sevPtr(severityRank(g.Severity)),
				})
				if err != nil {
					slog.Warn("incident upsert", "src_ip", srcIP, "err", err)
					continue
				}
				incidentID = created
			}

			stage := stageOrUnknown(g.Stage)
			stages = appendUnique(stages, stage)
			if r := severityRank(g.Severity); r < minSev {
				minSev = r
			}
			spanEnd = g.LastSeen.Time

			if err := q.AttachGroupToIncident(ctx, gen.AttachGroupToIncidentParams{
				IncidentID: incidentID,
				GroupID:    g.ID,
				StageOrder: int32(stageOrder[stage]),
			}); err != nil {
				slog.Warn("attach group", "group_id", g.ID, "err", err)
			}
		}
		flush()
	}
	return chained, nil
}

func stageSummary(stages []string) string {
	if len(stages) == 0 {
		return ""
	}
	sort.Slice(stages, func(i, j int) bool { return stageOrder[stages[i]] < stageOrder[stages[j]] })
	out := ""
	for i, s := range stages {
		if i > 0 {
			out += " → "
		}
		out += s
	}
	return out
}

func stageOrUnknown(s pgtype.Text) string {
	if !s.Valid || s.String == "" {
		return "unknown"
	}
	return s.String
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func sevPtr(v int32) pgtype.Int4 {
	if v >= 99 {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: v, Valid: true}
}
