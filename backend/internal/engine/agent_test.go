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
