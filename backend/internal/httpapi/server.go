package httpapi

import (
	"encoding/json"
	"net/http"

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
	r.Handle("GET /api/v1/alerts/{id}", authed(http.HandlerFunc(s.handleGetAlert)))
	r.Handle("GET /api/v1/alert-groups", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/overview", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/incidents", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/rules", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/pcaps", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/replay-tasks", authed(http.HandlerFunc(s.handleListTasks)))
	r.Handle("GET /api/v1/replay-tasks/{id}", authed(http.HandlerFunc(s.handleGetTask)))
	r.Handle("GET /api/v1/engine/status", authed(http.HandlerFunc(s.handleEngineStatus)))
	r.Handle("GET /api/v1/stream", authed(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/validation/latest", authed(http.HandlerFunc(s.notImplemented)))

	// analyst+
	analyst := s.auth.Middleware("analyst")
	r.Handle("POST /api/v1/pcaps", analyst(http.HandlerFunc(s.handleUploadPcap)))
	r.Handle("POST /api/v1/replay-tasks", analyst(http.HandlerFunc(s.handleCreateTask)))
	r.Handle("PATCH /api/v1/rules/{sid}", analyst(http.HandlerFunc(s.notImplemented)))
	r.Handle("PATCH /api/v1/alert-groups/{id}/status", analyst(http.HandlerFunc(s.notImplemented)))
	r.Handle("GET /api/v1/alerts/{id}/pcap", analyst(http.HandlerFunc(s.notImplemented)))

	return r
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
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
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
