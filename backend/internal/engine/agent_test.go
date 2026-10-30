package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleValidateRejectsBadInput(t *testing.T) {
	a := NewAgentServer("tok", "/nonexistent/suricata", "/nonexistent.sock")
	h := a.Handler()
	cases := []struct {
		name  string
		token string
		body  string
		want  int
	}{
		{name: "no token", token: "", body: `{"rules":"alert ip any any -> any any (sid:1;)"}`, want: http.StatusUnauthorized},
		{name: "not json", token: "tok", body: `rules=x`, want: http.StatusBadRequest},
		{name: "empty rules", token: "tok", body: `{"rules":"   "}`, want: http.StatusBadRequest},
		{name: "too large", token: "tok", body: `{"rules":"` + strings.Repeat("a", maxValidateBytes+1) + `"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/validate-rules", strings.NewReader(tc.body))
			if tc.token != "" {
				req.Header.Set("X-Agent-Token", tc.token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// 回放状态：入队后（进程尚未启动）不得报告空闲；进程失败后空闲并在 errors 中带出原因。
func TestReplayStateQueuedAndFailure(t *testing.T) {
	a := NewAgentServer("tok", "/nonexistent/suricata", "/nonexistent.sock")
	if got := a.replayState()["current"]; got != "None" {
		t.Fatalf("idle current = %v, want None", got)
	}
	a.mu.Lock()
	a.queued++
	a.mu.Unlock()
	if got := a.replayState()["current"]; got == "None" {
		t.Fatal("queued task reported as idle")
	}

	const taskID = "11111111-1111-1111-1111-111111111111"
	a.runReplay(taskID, "/nonexistent.pcap", t.TempDir())
	st := a.replayState()
	if st["current"] != "None" || st["queued"] != 0 {
		t.Fatalf("after run: current=%v queued=%v", st["current"], st["queued"])
	}
	errs := st["errors"].(map[string]string)
	if !strings.Contains(errs[taskID], "suricata -r failed") {
		t.Fatalf("missing failure for task: %v", errs)
	}
}
