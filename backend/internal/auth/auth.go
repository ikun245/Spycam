package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
)

const sessionPrefix = "sess:"

var (
	// ErrUnauthorized 会话缺失或已过期。
	ErrUnauthorized = errors.New("unauthorized")
	// ErrForbidden 角色权限不足。
	ErrForbidden = errors.New("forbidden")
)

// Service 管理会话与密码校验。
type Service struct {
	pool       *pgxpool.Pool
	rdb        *redis.Client
	sessionTTL time.Duration
}

// NewService 构造鉴权服务。
func NewService(pool *pgxpool.Pool, rdb *redis.Client, sessionTTL time.Duration) *Service {
	return &Service{pool: pool, rdb: rdb, sessionTTL: sessionTTL}
}

// Login 校验用户名密码，成功返回会话 ID（存 Redis，TTL 到期自动失效）。
func (s *Service) Login(ctx context.Context, username, password string) (sessionID, role string, err error) {
	var hash string
	qerr := s.pool.QueryRow(ctx,
		`SELECT password_hash, role FROM users WHERE username = $1`, username,
	).Scan(&hash, &role)
	if qerr != nil {
		// 统一返回未授权，不区分“用户不存在”与“密码错误”
		return "", "", ErrUnauthorized
	}
	if !verifyArgon2id(password, hash) {
		return "", "", ErrUnauthorized
	}
	sid, err := newSessionID()
	if err != nil {
		return "", "", fmt.Errorf("generate session: %w", err)
	}
	if err := s.rdb.Set(ctx, sessionPrefix+sid, username+"|"+role, s.sessionTTL).Err(); err != nil {
		return "", "", fmt.Errorf("store session: %w", err)
	}
	return sid, role, nil
}

// Logout 删除会话。
func (s *Service) Logout(ctx context.Context, sessionID string) {
	_ = s.rdb.Del(ctx, sessionPrefix+sessionID).Err()
}

// Identity 是请求上下文中的用户身份。
type Identity struct {
	Username string
	Role     string
}

// Middleware 校验 Cookie 中的会话，把 Identity 写入 context；minRole 非空时再校验角色。
func (s *Service) Middleware(minRole string) func(http.Handler) http.Handler {
	rank := map[string]int{"viewer": 1, "analyst": 2, "admin": 3}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie("spycam_session")
			if err != nil || c.Value == "" {
				unauthorized(w)
				return
			}
			val, err := s.rdb.Get(r.Context(), sessionPrefix+c.Value).Result()
			if err != nil {
				unauthorized(w)
				return
			}
			parts := strings.SplitN(val, "|", 2)
			if len(parts) != 2 {
				unauthorized(w)
				return
			}
			id := Identity{Username: parts[0], Role: parts[1]}
			if minRole != "" && rank[id.Role] < rank[minRole] {
				writeErr(w, http.StatusForbidden, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
		})
	}
}

type identityKey struct{}

// FromContext 取当前身份（未认证时返回 false）。
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// HashPassword 生成 argon2id 哈希（PHC 字符串格式）。
func HashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, 1, 19*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func verifyArgon2id(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 1, 19*1024, 2, uint32(len(want)))
	return string(got) == string(want)
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func unauthorized(w http.ResponseWriter) {
	writeErr(w, http.StatusUnauthorized, ErrUnauthorized)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, err.Error())
}

// SeedAdmin 首次启动时创建管理员（幂等，ON CONFLICT 跳过）。
func SeedAdmin(ctx context.Context, pool *pgxpool.Pool, username, password string) error {
	hash := HashPassword(password)
	tag, err := pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')
		 ON CONFLICT (username) DO NOTHING`,
		username, hash)
	if err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}
	if tag.RowsAffected() > 0 {
		slog.Info("seed admin created", "username", username)
	}
	return nil
}
