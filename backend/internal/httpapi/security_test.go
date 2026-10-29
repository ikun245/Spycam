package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireCSRFHeader(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := requireCSRFHeader(ok)

	tests := []struct {
		name   string
		method string
		path   string
		header string
		want   int
	}{
		{"GET 不校验", http.MethodGet, "/api/v1/alerts", "", http.StatusNoContent},
		{"POST 缺头拒绝", http.MethodPost, "/api/v1/replay-tasks", "", http.StatusForbidden},
		{"登录同样校验", http.MethodPost, "/api/v1/auth/login", "", http.StatusForbidden},
		{"PATCH 头值错误拒绝", http.MethodPatch, "/api/v1/rules/1000001", "XMLHttpRequest", http.StatusForbidden},
		{"POST 带正确头放行", http.MethodPost, "/api/v1/replay-tasks", "spycam", http.StatusNoContent},
		{"非 /api 路径不校验", http.MethodPost, "/healthz", "", http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.header != "" {
				req.Header.Set("X-Requested-With", tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestClientIPUsesNginxAppendedValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "172.18.0.5:41000"
	// 客户端伪造的 1.2.3.4 在最左，nginx 追加的真实地址在最右
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 172.18.0.1")
	if got := clientIP(req); got != "172.18.0.1" {
		t.Errorf("clientIP = %q, want nginx 追加的最后一个值", got)
	}
	req.Header.Del("X-Forwarded-For")
	if got := clientIP(req); got != "172.18.0.5" {
		t.Errorf("clientIP without XFF = %q", got)
	}
}

func TestValidateRuleHeaderFields(t *testing.T) {
	base := func() createRuleRequest {
		return createRuleRequest{SrcIP: "any", SrcPort: "any", DstIP: "$HOME_NET", DstPort: "22"}
	}
	ok := []func(*createRuleRequest){
		func(r *createRuleRequest) {},
		func(r *createRuleRequest) { r.SrcIP = "10.0.0.0/8"; r.DstPort = "[80,443]" },
		func(r *createRuleRequest) { r.SrcIP = "!192.168.1.1"; r.SrcPort = "1024:65535" },
		func(r *createRuleRequest) { r.DstIP = "[10.0.0.1,10.0.0.2]"; r.MitreTactic = "TA0006 Credential Access" },
		func(r *createRuleRequest) { r.SrcIP = "fe80::1"; r.MitreTechnique = "T1110.001" },
	}
	for i, mut := range ok {
		r := base()
		mut(&r)
		if err := validateRuleHeaderFields(&r); err != nil {
			t.Errorf("ok case %d rejected: %v", i, err)
		}
	}
	bad := []func(*createRuleRequest){
		func(r *createRuleRequest) { r.SrcIP = "any -> any any (msg:\"x\"; sid:1;)" },
		func(r *createRuleRequest) { r.SrcPort = "80 (pcre:/x/;)" },
		func(r *createRuleRequest) { r.DstPort = "abc" },
		func(r *createRuleRequest) { r.MitreTactic = "x; pcre:\"/a/\"" },
		func(r *createRuleRequest) { r.MitreTechnique = "a, author evil" },
	}
	for i, mut := range bad {
		r := base()
		mut(&r)
		if err := validateRuleHeaderFields(&r); err == nil {
			t.Errorf("bad case %d accepted: %+v", i, r)
		}
	}
}

func TestASCIIFallbackStripsRuleMetachars(t *testing.T) {
	got := asciiFallback(`x"; pcre:"/a/"; \`, 2000001)
	if strings.ContainsAny(got, "\";\\") {
		t.Errorf("asciiFallback 未剥离规则元字符: %q", got)
	}
}
