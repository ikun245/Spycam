package observability

import (
	"context"
	"net/http"
)

// Check 是单个依赖的就绪检查。
type Check func(ctx context.Context) error

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"status":` + statusText(v, status) + `}`))
}

func statusText(_ any, status int) string {
	if status == http.StatusOK {
		return `"ok"`
	}
	return `"unavailable"`
}

// HealthzHandler 仅表示进程存活。
func HealthzHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, nil)
}

// ReadyHandler 逐一探测依赖，任一失败返回 503。
func ReadyHandler(checks map[string]Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		results := make(map[string]string, len(checks))
		for name, check := range checks {
			if err := check(r.Context()); err != nil {
				results[name] = "fail: " + err.Error()
				status = http.StatusServiceUnavailable
			} else {
				results[name] = "ok"
			}
		}
		writeJSON(w, status, results)
	}
}
