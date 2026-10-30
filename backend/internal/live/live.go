// Package live 实现在线抓包（C1）的持续采集：tail 实时 Suricata 写出的 eve.json，
// 增量入库后立即聚合、串联并经 SSE 推送，使告警延迟降到秒级。
package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/aggregate"
	"spycam/backend/internal/incident"
	"spycam/backend/internal/ingest"
	"spycam/backend/internal/realtime"
	"spycam/backend/internal/store/gen"
)

// SampleType 标记在线抓包数据源；它没有原始 pcap 文件，取证导出据此拒绝。
const SampleType = "live"

// Tailer 持续采集一个网卡对应的 eve.json。
type Tailer struct {
	Pool      *pgxpool.Pool
	Redis     *redis.Client
	Pub       *realtime.Publisher
	EvePath   string
	Iface     string
	AggWindow int
	Interval  time.Duration
}

// IDs 由网卡名确定性派生数据源与任务 ID：重启后继续写入同一任务，offset 也随之复用。
func IDs(iface string) (pcapID, taskID string) {
	return deriveUUID("spycam-live-pcap:" + iface), deriveUUID("spycam-live-task:" + iface)
}

func deriveUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // 基于名字的 version 5 风格
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// ensureTask 幂等创建在线数据源与常驻任务（status=running）。
func ensureTask(ctx context.Context, q *gen.Queries, iface string) (string, error) {
	pcapID, taskID := IDs(iface)
	if _, err := q.GetPcap(ctx, pcapID); errors.Is(err, pgx.ErrNoRows) {
		if err := q.CreatePcap(ctx, gen.CreatePcapParams{
			ID:           pcapID,
			OriginalName: "live:" + iface,
			StoredPath:   "live://" + iface,
			SampleType:   SampleType,
		}); err != nil {
			return "", fmt.Errorf("create live source: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("get live source: %w", err)
	}
	if _, err := q.GetTask(ctx, taskID); errors.Is(err, pgx.ErrNoRows) {
		if err := q.CreateTask(ctx, gen.CreateTaskParams{ID: taskID, PcapID: pcapID}); err != nil {
			return "", fmt.Errorf("create live task: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("get live task: %w", err)
	}
	if err := q.UpdateTaskStatus(ctx, gen.UpdateTaskStatusParams{ID: taskID, Status: "running"}); err != nil {
		return "", fmt.Errorf("mark live task running: %w", err)
	}
	return taskID, nil
}

func offsetKey(taskID string) string { return "live:eve_offset:" + taskID }

// Run 阻塞运行直到 ctx 取消。eve.json 尚不存在（未启用 live profile）时静默等待。
func (t *Tailer) Run(ctx context.Context) {
	q := gen.New(t.Pool)
	interval := t.Interval
	if interval <= 0 {
		interval = time.Second
	}
	var taskID string
	waitingLogged := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := os.Stat(t.EvePath); err != nil {
			if !waitingLogged {
				slog.Info("live eve not present, waiting (enable with --profile live)", "path", t.EvePath)
				waitingLogged = true
			}
			continue
		}
		if taskID == "" {
			id, err := ensureTask(ctx, q, t.Iface)
			if err != nil {
				slog.Error("live ensure task", "err", err)
				continue
			}
			taskID = id
			slog.Info("live capture ingest started", "task_id", taskID, "iface", t.Iface, "path", t.EvePath)
		}
		t.poll(ctx, taskID)
	}
}

func (t *Tailer) poll(ctx context.Context, taskID string) {
	offset, err := t.Redis.Get(ctx, offsetKey(taskID)).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("live offset read", "task_id", taskID, "err", err)
		return
	}
	res, next, err := ingest.IngestFrom(ctx, t.Pool, taskID, t.EvePath, offset)
	if next != offset {
		if serr := t.Redis.Set(ctx, offsetKey(taskID), strconv.FormatInt(next, 10), 0).Err(); serr != nil {
			slog.Warn("live offset save", "task_id", taskID, "err", serr)
		}
	}
	if err != nil {
		slog.Warn("live ingest", "task_id", taskID, "err", err)
	}
	if res.Alerts == 0 {
		return
	}
	if _, err := aggregate.GroupAlerts(ctx, t.Pool, taskID, t.AggWindow); err != nil {
		slog.Warn("live aggregate", "task_id", taskID, "err", err)
	}
	incidents, err := incident.ChainTask(ctx, t.Pool, taskID)
	if err != nil {
		slog.Warn("live incident chain", "task_id", taskID, "err", err)
	}
	t.Pub.Publish(ctx, realtime.Event{Type: "live", TaskID: taskID, Status: "running",
		Alerts: res.Alerts, Incidents: incidents})
	slog.Info("live alerts ingested", "task_id", taskID, "alerts", res.Alerts,
		"events", res.Events, "skipped", res.Skipped, "offset", next)
}
