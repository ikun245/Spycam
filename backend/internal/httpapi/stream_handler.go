package httpapi

import (
	"fmt"
	"net/http"

	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/realtime"
)

// handleStream SSE 实时推送（C1）：新告警组、任务状态变化。
// 事件格式：event: alert / data: {json}
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
	go realtime.Subscribe(ctx, s.rdb, msgs)

	// 初始注释行，触发浏览器 EventSource onopen
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgs:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: alert\ndata: %s\n\n", msg.Payload)
			fl.Flush()
		}
	}
}
