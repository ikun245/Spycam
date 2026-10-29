package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/auth"
	"spycam/backend/internal/config"
	"spycam/backend/internal/engine"
)

// Server 装配 REST API 路由（架构设计 §6.3）。
type Server struct {
	cfg    *config.Config
	auth   *auth.Service
	agent  *engine.Client
	pool   *pgxpool.Pool
	rdb    *redis.Client
	ready  http.HandlerFunc
	health http.HandlerFunc
}

// NewServer 构造 API Server.
func NewServer(cfg *config.Config, authSvc *auth.Service, agent *engine.Client, pool *pgxpool.Pool, rdb *redis.Client, health, ready http.HandlerFunc) *Server {
	return &Server{cfg: cfg, auth: authSvc, agent: agent, pool: pool, rdb: rdb, health: health, ready: ready}
}

// Handler 返回完整路由。
func (s *Server) Handler() http.Handler {
	r := http.NewServeMux()

	// 健康探针：nginx 透传保留 /api 前缀，故注册带前缀路径；同时保留裸路径供容器内直连探测
	r.HandleFunc("GET /healthz", s.health)
	r.HandleFunc("GET /readyz", s.ready)
	r.HandleFunc("GET /api/v1/healthz", s.health)
	r.HandleFunc("GET /api/v1/readyz", s.ready)

	// 公开：登录
	r.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	r.Handle("POST /api/v1/auth/logout", s.auth.Middleware("")(http.HandlerFunc(s.handleLogout)))

	// 需要登录（viewer+）
	authed := s.auth.Middleware("viewer")
	r.Handle("GET /api/v1/auth/me", authed(http.HandlerFunc(s.handleMe)))
	r.Handle("GET /api/v1/alerts", authed(http.HandlerFunc(s.handleListAlerts)))
	r.Handle("GET /api/v1/alerts/{id}", authed(http.HandlerFunc(s.handleGetAlertRaw)))
	r.Handle("GET /api/v1/overview", authed(http.HandlerFunc(s.handleOverview)))
	r.Handle("GET /api/v1/rules", authed(http.HandlerFunc(s.handleListRules)))
	r.Handle("GET /api/v1/alert-groups", authed(http.HandlerFunc(s.handleListGroups)))
	r.Handle("GET /api/v1/incidents", authed(http.HandlerFunc(s.handleListIncidents)))
	r.Handle("GET /api/v1/incidents/{id}", authed(http.HandlerFunc(s.handleGetIncident)))
	r.Handle("GET /api/v1/pcaps", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/replay-tasks", authed(http.HandlerFunc(s.handleListTasks)))
	r.Handle("GET /api/v1/replay-tasks/{id}", authed(http.HandlerFunc(s.handleGetTask)))
	r.Handle("GET /api/v1/engine/status", authed(http.HandlerFunc(s.handleEngineStatusV2)))
	r.Handle("GET /api/v1/stream", authed(http.HandlerFunc(s.handleStream)))

	// analyst+
	analyst := s.auth.Middleware("analyst")
	r.Handle("POST /api/v1/pcaps", analyst(http.HandlerFunc(s.handleUploadPcap)))
	r.Handle("POST /api/v1/replay-tasks", analyst(http.HandlerFunc(s.handleCreateTask)))
	r.Handle("POST /api/v1/rules", analyst(http.HandlerFunc(s.handleCreateRule)))
	r.Handle("PATCH /api/v1/rules/{sid}", analyst(http.HandlerFunc(s.handleToggleRule)))
	r.Handle("PATCH /api/v1/alert-groups/{id}/status", analyst(http.HandlerFunc(s.handleTriageGroup)))
	r.Handle("GET /api/v1/alerts/{id}/pcap", analyst(http.HandlerFunc(s.handleExportAlertPcap)))

	// admin：审计日志
	admin := s.auth.Middleware("admin")
	r.Handle("GET /api/v1/audit-log", admin(http.HandlerFunc(s.handleListAudit)))

	return requireCSRFHeader(r)
}

// requireCSRFHeader 对 /api/ 下所有非安全方法强制自定义请求头（架构设计 §6.6）。
// 跨站表单无法设置自定义头，带头的跨源 fetch 会触发 CORS 预检而被拒，
// 与 SameSite=Strict Cookie 叠加构成双层 CSRF 防护；登录接口同样校验，防登录 CSRF。
func requireCSRFHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Requested-With") != "spycam" {
				writeErr(w, http.StatusForbidden, "missing X-Requested-With header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	sid, _, err := s.auth.Login(r.Context(), req.Username, req.Password)
	if errors.Is(err, auth.ErrLocked) {
		s.audit(r.Context(), req.Username, auditLoginLocked, req.Username, map[string]any{"ip": clientIP(r)})
		writeErr(w, http.StatusTooManyRequests, "登录失败次数过多，请 15 分钟后再试")
		return
	}
	if err != nil {
		s.audit(r.Context(), req.Username, auditLoginFail, req.Username, map[string]any{"ip": clientIP(r)})
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	s.audit(r.Context(), req.Username, auditLoginOK, req.Username, map[string]any{"ip": clientIP(r)})
	http.SetCookie(w, &http.Cookie{
		Name:     "spycam_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("spycam_session"); err == nil {
		s.auth.Logout(r.Context(), c.Value)
	}
	s.audit(r.Context(), actor(r), auditLogout, actor(r), nil)
	http.SetCookie(w, &http.Cookie{Name: "spycam_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.FromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, id)
}

func (s *Server) handleEngineStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.agent.Status(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "engine agent unreachable")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusNotImplemented, "not implemented in skeleton")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// clientIP 取客户端 IP 供审计。api 不对外发布端口，只有 web(nginx) 能访问；
// nginx 用 $proxy_add_x_forwarded_for 把真实对端地址追加在末尾，最左侧的值可被客户端伪造，
// 因此只取最后一个元素；缺失时退回连接地址。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
