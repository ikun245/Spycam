// Package live 实现在线抓包（C1）的持续采集：tail 实时 Suricata 写出的 eve.json，
// 增量入库后立即聚合、串联并经 SSE 推送，使告警延迟降到秒级。
package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/aggregate"
	"spycam/backend/internal/incident"
	"spycam/backend/internal/ingest"
	"spycam/backend/internal/realtime"
	"spycam/backend/internal/store/gen"
)

// SampleType 标记在线抓包数据源；它没有原始 pcap 文件，取证导出据此拒绝。
const SampleType = "live"

// Tailer 持续采集一个网卡对应的 eve.json。
type Tailer struct {
	Pool      *pgxpool.Pool
	Redis     *redis.Client
	Pub       *realtime.Publisher
	EvePath   string
	// Iface 为配置的网卡名；IfaceFile 存在时以 suricata-live 写出的实际网卡名为准（自动探测场景）
	Iface     string
	IfaceFile string
	AggWindow int
	Interval  time.Duration
}

// resolveIface 返回实际监听的网卡名：优先读取 IfaceFile，其次配置值，都没有时为 "auto"。
func (t *Tailer) resolveIface() string {
	if t.IfaceFile != "" {
		if b, err := os.ReadFile(t.IfaceFile); err == nil {
			if name := strings.TrimSpace(string(b)); validIface(name) {
				return name
			}
		}
	}
	if validIface(t.Iface) {
		return t.Iface
	}
	return "auto"
}

// validIface 与 entrypoint-live.sh 的白名单一致；Linux 网卡名最长 15 字节
func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// IDs 由网卡名确定性派生数据源与任务 ID：重启后继续写入同一任务，offset 也随之复用。
func IDs(iface string) (pcapID, taskID string) {
	return deriveUUID("spycam-live-pcap:" + iface), deriveUUID("spycam-live-task:" + iface)
}

func deriveUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // 基于名字的 version 5 风格
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// ensureTask 幂等创建在线数据源与常驻任务（status=running）。
func ensureTask(ctx context.Context, q *gen.Queries, iface string) (string, error) {
	pcapID, taskID := IDs(iface)
	if _, err := q.GetPcap(ctx, pcapID); errors.Is(err, pgx.ErrNoRows) {
		if err := q.CreatePcap(ctx, gen.CreatePcapParams{
			ID:           pcapID,
			OriginalName: "live:" + iface,
			StoredPath:   "live://" + iface,
			SampleType:   SampleType,
		}); err != nil {
			return "", fmt.Errorf("create live source: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("get live source: %w", err)
	}
	if _, err := q.GetTask(ctx, taskID); errors.Is(err, pgx.ErrNoRows) {
		if err := q.CreateTask(ctx, gen.CreateTaskParams{ID: taskID, PcapID: pcapID}); err != nil {
			return "", fmt.Errorf("create live task: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("get live task: %w", err)
	}
	if err := q.UpdateTaskStatus(ctx, gen.UpdateTaskStatusParams{ID: taskID, Status: "running"}); err != nil {
		return "", fmt.Errorf("mark live task running: %w", err)
	}
	return taskID, nil
}

func offsetKey(taskID string) string { return "live:eve_offset:" + taskID }

// cursor 记录读到哪个文件（inode）的哪个字节位置；Redis 中存为 "inode:offset"。
type cursor struct {
	Ino uint64
	Off int64
}

func (c cursor) String() string { return fmt.Sprintf("%d:%d", c.Ino, c.Off) }

// parseCursor 兼容旧格式（只有 offset 的纯数字）；无法解析时从头开始。
func parseCursor(s string) cursor {
	if s == "" {
		return cursor{}
	}
	if ino, off, ok := strings.Cut(s, ":"); ok {
		i, err1 := strconv.ParseUint(ino, 10, 64)
		o, err2 := strconv.ParseInt(off, 10, 64)
		if err1 == nil && err2 == nil && o >= 0 {
			return cursor{Ino: i, Off: o}
		}
		return cursor{}
	}
	if o, err := strconv.ParseInt(s, 10, 64); err == nil && o >= 0 {
		return cursor{Off: o}
	}
	return cursor{}
}

// rotatedSuffix 与 entrypoint-live.sh 的轮转约定一致：eve.json → eve.json.1 后 SIGHUP 让 Suricata 重新打开。
const rotatedSuffix = ".1"

type readFn func(f *os.File, offset int64) (ingest.Result, int64, error)

// advance 从游标继续读取 path；检测到轮转（inode 变化，或无 inode 时文件变短）时，
// 先把旧文件（path+".1"）剩余部分读完，再从新文件开头读，保证轮转不丢告警。
func advance(path string, c cursor, read readFn) (cursor, ingest.Result, error) {
	var total ingest.Result
	f, err := os.Open(path)
	if err != nil {
		return c, total, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return c, total, err
	}
	ino := fileID(fi)
	rotated := fi.Size() < c.Off
	if c.Ino != 0 && ino != 0 {
		rotated = c.Ino != ino
	}
	if rotated {
		if old, oerr := os.Open(path + rotatedSuffix); oerr == nil {
			if ofi, serr := old.Stat(); serr == nil &&
				(c.Ino == 0 || fileID(ofi) == c.Ino) && ofi.Size() >= c.Off {
				r, _, rerr := read(old, c.Off)
				addResult(&total, r)
				if rerr != nil {
					slog.Warn("live drain rotated eve", "err", rerr)
				}
			}
			old.Close()
		}
		slog.Info("live eve rotated, switching to new file", "path", path)
		c = cursor{}
	}
	c.Ino = ino
	r, next, err := read(f, c.Off)
	addResult(&total, r)
	c.Off = next
	return c, total, err
}

func addResult(dst *ingest.Result, r ingest.Result) {
	dst.Events += r.Events
	dst.Alerts += r.Alerts
	dst.Skipped += r.Skipped
}

// Run 阻塞运行直到 ctx 取消。eve.json 尚不存在（未启用 live profile）时静默等待。
func (t *Tailer) Run(ctx context.Context) {
	q := gen.New(t.Pool)
	interval := t.Interval
	if interval <= 0 {
		interval = time.Second
	}
	var taskID string
	waitingLogged := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := os.Stat(t.EvePath); err != nil {
			if !waitingLogged {
				slog.Info("live eve not present, waiting (enable with --profile live)", "path", t.EvePath)
				waitingLogged = true
			}
			continue
		}
		if taskID == "" {
			iface := t.resolveIface()
			id, err := ensureTask(ctx, q, iface)
			if err != nil {
				slog.Error("live ensure task", "err", err)
				continue
			}
			taskID = id
			slog.Info("live capture ingest started", "task_id", taskID, "iface", iface, "path", t.EvePath)
		}
		t.poll(ctx, taskID)
	}
}

func (t *Tailer) poll(ctx context.Context, taskID string) {
	raw, err := t.Redis.Get(ctx, offsetKey(taskID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("live offset read", "task_id", taskID, "err", err)
		return
	}
	cur := parseCursor(raw)
	next, res, err := advance(t.EvePath, cur, func(f *os.File, off int64) (ingest.Result, int64, error) {
		return ingest.IngestOpenFile(ctx, t.Pool, taskID, ingest.SourceLive, f, off)
	})
	if next != cur {
		if serr := t.Redis.Set(ctx, offsetKey(taskID), next.String(), 0).Err(); serr != nil {
			slog.Warn("live offset save", "task_id", taskID, "err", serr)
		}
	}
	if err != nil {
		slog.Warn("live ingest", "task_id", taskID, "err", err)
	}
	if res.Alerts == 0 {
		return
	}
	if _, err := aggregate.GroupAlerts(ctx, t.Pool, taskID, t.AggWindow); err != nil {
		slog.Warn("live aggregate", "task_id", taskID, "err", err)
	}
	incidents, err := incident.ChainTask(ctx, t.Pool, taskID)
	if err != nil {
		slog.Warn("live incident chain", "task_id", taskID, "err", err)
	}
	t.Pub.Publish(ctx, realtime.Event{Type: "live", TaskID: taskID, Status: "running",
		Alerts: res.Alerts, Incidents: incidents})
	slog.Info("live alerts ingested", "task_id", taskID, "alerts", res.Alerts,
		"events", res.Events, "skipped", res.Skipped, "offset", next)
}
