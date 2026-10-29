package httpapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/realtime"
)

// handleStream SSE 实时推送（C1）：任务状态变化与新增告警统计。
// 事件格式：event: task / data: {realtime.Event JSON}；每 25 秒发注释心跳，防止代理断开空闲连接。
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	msgs := make(chan *redis.Message, 16)
	ctx := r.Context()
	realtime.Subscribe(ctx, s.rdb, msgs)

	// retry 告诉浏览器断线 3 秒后重连；初始注释行触发 EventSource onopen
	fmt.Fprint(w, "retry: 3000\n: connected\n\n")
	fl.Flush()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case msg, ok := <-msgs:
			if !ok {
				return
			}
			// payload 由 worker 经 json.Marshal 生成，不含换行，可直接作为单行 data
			fmt.Fprintf(w, "event: task\ndata: %s\n\n", msg.Payload)
			fl.Flush()
		}
	}
}
