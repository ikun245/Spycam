// Package aggregate 实现告警聚合（S1）：同签名 + 同五元组合并为组，
// 保留全部原始告警（评测用 view=raw 不受影响，架构设计 §3.4）。
package aggregate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"spycam/backend/internal/store/gen"
)

// GroupAlerts 把指定任务的全部未分组告警按 sid+五元组+N 秒窗口聚合。
// 幂等：只处理 group_id IS NULL 的行。
func GroupAlerts(ctx context.Context, pool *pgxpool.Pool, taskID string, windowSeconds int) (int, error) {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	q := gen.New(pool)
	rows, err := q.ListUnGroupedAlerts(ctx, taskID)
	if err != nil {
		return 0, fmt.Errorf("list ungrouped: %w", err)
	}
	grouped := 0
	for _, a := range rows {
		var ts int64
		if a.Ts.Valid {
			ts = a.Ts.Time.Unix()
		}
		// 时间分桶：同一 N 秒窗口内的同五元组告警合并为一条，跨窗口另起新组，
		// 避免长期持续攻击被永久并成单条（S1：N 可配，且不吞掉多阶段攻击）。
		bucket := ts / int64(windowSeconds)
		hash := GroupHash(a.Sid, a.SrcIp, a.SrcPort.Int32, a.DestIp, a.DestPort.Int32, a.Proto.String, bucket)
		g, err := q.UpsertAlertGroup(ctx, gen.UpsertAlertGroupParams{
			GroupHash: hash,
			Sid:       a.Sid,
			SrcIp:     a.SrcIp,
			SrcPort:   a.SrcPort,
			DestIp:    a.DestIp,
			DestPort:  a.DestPort,
			Proto:     a.Proto,
			FirstSeen: pgtype.Timestamptz{Time: a.Ts.Time, Valid: true},
		})
		if err != nil {
			slog.Warn("group upsert failed", "task_id", taskID, "sid", a.Sid, "err", err)
			continue
		}
		if err := q.AttachAlertToGroup(ctx, gen.AttachAlertToGroupParams{
			ID:      a.ID,
			GroupID: pgtype.Int8{Int64: g.ID, Valid: true},
		}); err != nil {
			slog.Warn("attach alert failed", "alert_id", a.ID, "err", err)
			continue
		}
		grouped++
	}
	return grouped, nil
}

// GroupHash 生成分组键：sid + 五元组 + 时间窗口桶。
func GroupHash(sid int64, srcIP string, srcPort int32, destIP string, destPort int32, proto string, bucket int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%d|%s|%d|%s|%d",
		sid, srcIP, srcPort, destIP, destPort, proto, bucket)))
	return hex.EncodeToString(h[:16])
}
