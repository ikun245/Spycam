package realtime

import (
	"context"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// Channel 告警实时推送频道（架构设计 §3.3）。
const Channel = "chan:alerts"

// Publisher 把新告警发布到 Redis Pub/Sub，api 侧订阅后经 SSE 推给浏览器。
type Publisher struct {
	rdb *redis.Client
}

// NewPublisher 构造发布端。
func NewPublisher(rdb *redis.Client) *Publisher { return &Publisher{rdb: rdb} }

// PublishAlert 发布一条告警消息（骨架期消息体为原始 JSON 字符串）。
func (p *Publisher) PublishAlert(ctx context.Context, payload []byte) error {
	if err := p.rdb.Publish(ctx, Channel, payload).Err(); err != nil {
		return err
	}
	return nil
}

// Subscribe 订阅频道，消息经 out 传出；ctx 取消时退出。
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
