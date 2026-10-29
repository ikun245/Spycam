package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/aggregate"
	"spycam/backend/internal/config"
	"spycam/backend/internal/engine"
	"spycam/backend/internal/ingest"
	"spycam/backend/internal/incident"
	"spycam/backend/internal/realtime"
	"spycam/backend/internal/store/gen"
)

const replayQueue = "queue:replay"

// worker 负责回放调度、eve.json 采集归一化、聚合与事件串联（架构设计 §6.4）。
// P0 数据面：BRPOP 消费回放队列 → agent 提交 pcap-file → 轮询完成 → 采集 eve 入库。
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("pg connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("redis ping", "err", err)
		os.Exit(1)
	}

	queries := gen.New(pool)
	pub := realtime.NewPublisher(rdb)
	agent := engine.NewClient(cfg.EngineAgentURL, cfg.EngineAgentToken)
	eveRoot := os.Getenv("EVE_OUT_DIR")
	if eveRoot == "" {
		eveRoot = "/var/log/suricata"
	}

	// 启动时恢复可能因重启遗留的 queued 任务（架构设计 §3.3：PG 是任务真相）
	if queued, err := queries.ListQueuedTasks(ctx); err == nil && len(queued) > 0 {
		for _, id := range queued {
			if err := rdb.LPush(ctx, replayQueue, id).Err(); err != nil {
				slog.Error("requeue task", "task_id", id, "err", err)
			} else {
				slog.Info("requeued orphan task", "task_id", id)
			}
		}
	}

	slog.Info("worker started",
		"agg_window_seconds", cfg.AggWindowSeconds,
		"eve_out_dir", eveRoot)

	for {
		select {
		case <-ctx.Done():
			slog.Info("worker stopped")
			return
		default:
		}
		taskID, err := rdb.BRPop(ctx, 5*time.Second, replayQueue).Result()
		if err != nil {
			if err != redis.Nil {
				slog.Error("brpop", "err", err)
				time.Sleep(time.Second)
			}
			continue
		}
		if len(taskID) < 2 {
			continue
		}
		runTask(ctx, queries, agent, pool, pub, eveRoot, taskID[1], cfg.AggWindowSeconds)
	}
}

func runTask(ctx context.Context, queries *gen.Queries, agent *engine.Client, pool *pgxpool.Pool, pub *realtime.Publisher, eveRoot, taskID string, aggWindow int) {
	start := time.Now()
	slog.Info("task start", "task_id", taskID)

	task, err := queries.GetTask(ctx, taskID)
	if err != nil {
		slog.Error("task not found, drop", "task_id", taskID, "err", err)
		return
	}
	_ = queries.UpdateTaskStatus(ctx, gen.UpdateTaskStatusParams{ID: taskID, Status: "running"})
	pub.Publish(ctx, realtime.Event{Type: "task", TaskID: taskID, Status: "running"})
	finishErr := func(ctx context.Context, queries *gen.Queries, taskID, msg string) {
		failTask(ctx, queries, taskID, msg)
		pub.Publish(ctx, realtime.Event{Type: "task", TaskID: taskID, Status: "failed", Error: msg})
	}

	// 1. 提交引擎回放
	if _, err := agent.Replay(ctx, taskID, task.PcapID); err != nil {
		finishErr(ctx, queries, taskID, "replay submit: "+err.Error())
		return
	}

	// 2. 等待输出目录出现
	outDir := filepath.Join(eveRoot, "tasks", taskID)
	if err := ingest.WaitDir(ctx, outDir, 30*time.Second); err != nil {
		finishErr(ctx, queries, taskID, err.Error())
		return
	}

	// 3. 轮询引擎直到该 pcap 处理完成（pcap-current 不再指向本任务）
	if err := waitReplayDone(ctx, agent, taskID, 5*time.Minute); err != nil {
		finishErr(ctx, queries, taskID, err.Error())
		return
	}

	// 4. 采集 eve 入库（flow 刷新可能滞后，先固定等待 3 秒再采集）
	time.Sleep(3 * time.Second)
	res, err := ingest.IngestTask(ctx, pool, taskID, outDir)
	if err != nil {
		finishErr(ctx, queries, taskID, "ingest: "+err.Error())
		return
	}

	// 5. 聚合（S1）：sid+五元组+N 秒窗口分组，保留原始告警
	if n, err := aggregate.GroupAlerts(ctx, pool, taskID, aggWindow); err != nil {
		slog.Warn("aggregate failed", "task_id", taskID, "err", err)
	} else {
		slog.Info("aggregated", "task_id", taskID, "alerts_grouped", n,
			"window_seconds", aggWindow)
	}

	// 6. 事件串联（S3）：同源 IP 告警组按时间窗归入攻击事件
	incidents := 0
	if n, err := incident.ChainTask(ctx, pool, taskID); err != nil {
		slog.Warn("incident chain failed", "task_id", taskID, "err", err)
	} else {
		incidents = n
		slog.Info("incidents chained", "task_id", taskID, "incidents", n)
	}

	_ = queries.FinishTask(ctx, gen.FinishTaskParams{ID: taskID, Status: "done", Error: pgtext("")})
	pub.Publish(ctx, realtime.Event{Type: "task", TaskID: taskID, Status: "done",
		Alerts: res.Alerts, Incidents: incidents})
	slog.Info("task done", "task_id", taskID,
		"elapsed_ms", time.Since(start).Milliseconds(),
		"events", res.Events, "alerts", res.Alerts, "skipped", res.Skipped)
}

func waitReplayDone(ctx context.Context, agent *engine.Client, taskID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := agent.ReplayStatus(ctx)
		if err != nil {
			return err
		}
		// pcap-current 空闲时返回字符串 "None"，处理中返回 {filename:...}
		if s, ok := st["current"].(string); ok && s == "None" {
			return nil // 引擎空闲：当前没有正在处理的 pcap
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("replay not finished within %s", timeout)
}

func failTask(ctx context.Context, queries *gen.Queries, taskID, msg string) {
	slog.Error("task failed", "task_id", taskID, "err", msg)
	_ = queries.FinishTask(ctx, gen.FinishTaskParams{ID: taskID, Status: "failed", Error: pgtext(msg)})
}

func pgtext(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
