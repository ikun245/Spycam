package realtime

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// Channel 实时推送频道（架构设计 §3.3）：worker 发布，api 订阅后经 SSE 推给浏览器。
const Channel = "chan:alerts"

// Event 是推送给前端的消息。离线回放模式下告警在任务采集完成时批量入库，
// 因此以任务生命周期为粒度推送：running → done（携带新增告警/告警组/事件数）或 failed。
type Event struct {
	Type      string `json:"type"` // task
	TaskID    string `json:"task_id"`
	Status    string `json:"status"` // running|done|failed
	Alerts    int64  `json:"alerts,omitempty"`
	Incidents int    `json:"incidents,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Publisher 把事件发布到 Redis Pub/Sub。
type Publisher struct {
	rdb *redis.Client
}

// NewPublisher 构造发布端。
func NewPublisher(rdb *redis.Client) *Publisher { return &Publisher{rdb: rdb} }

// Publish 发布一条事件；推送是尽力而为，失败只记日志，不影响任务本身（前端仍有轮询兜底）。
func (p *Publisher) Publish(ctx context.Context, ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		slog.Error("realtime marshal", "err", err)
		return
	}
	if err := p.rdb.Publish(ctx, Channel, b).Err(); err != nil {
		slog.Warn("realtime publish", "task_id", ev.TaskID, "err", err)
	}
}

// Subscribe 订阅频道，消息经 out 传出；ctx 取消或订阅失败时关闭 out。
func Subscribe(ctx context.Context, rdb *redis.Client, out chan<- *redis.Message) {
	sub := rdb.Subscribe(ctx, Channel)
	go func() {
		<-ctx.Done()
		_ = sub.Close()
	}()
	go func() {
		defer close(out)
		if _, err := sub.Receive(ctx); err != nil {
			slog.Error("subscribe receive", "err", err)
			return
		}
		for msg := range sub.Channel() {
			select {
			case out <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()
}
