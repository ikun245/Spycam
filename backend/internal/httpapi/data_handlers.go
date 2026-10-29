package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"spycam/backend/internal/store/gen"
)

const replayQueue = "queue:replay"

// handleUploadPcap 接收 multipart 上传：忽略原始文件名，UUID 落盘（M7 路径穿越防护）。
func (s *Server) handleUploadPcap(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil { // 64MB 上限
		writeErr(w, http.StatusBadRequest, "multipart parse failed")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	// 魔数校验：pcap(0xa1b2c3d4 / 0xa1b23c4d) 或 pcapng(0x0a0d0d0a)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(file, magic); err != nil {
		writeErr(w, http.StatusBadRequest, "file too small")
		return
	}
	if !isPcapMagic(magic) {
		writeErr(w, http.StatusBadRequest, "not a pcap/pcapng file")
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, "rewind failed")
		return
	}

	id := uuid.New()
	storedPath := filepath.Join(s.cfg.PcapsDir, id.String()+".pcap")
	out, err := os.Create(storedPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "storage unavailable")
		return
	}
	defer out.Close()
	// 落盘的同时计算全文件 sha256，避免二次读盘
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, hasher), file)
	if err != nil {
		_ = os.Remove(storedPath)
		writeErr(w, http.StatusInternalServerError, "write failed")
		return
	}
	sum := hex.EncodeToString(hasher.Sum(nil))

	q := gen.New(s.pool)
	if err := q.CreatePcap(r.Context(), gen.CreatePcapParams{
		ID:           id.String(),
		OriginalName: sanitizeName(r.FormValue("name")),
		StoredPath:   storedPath,
		SizeBytes:    size,
		Sha256:       pgtype.Text{String: sum, Valid: true},
		SampleType:   r.FormValue("sample_type"),
	}); err != nil {
		_ = os.Remove(storedPath)
		writeErr(w, http.StatusInternalServerError, "db insert failed")
		return
	}
	s.audit(r.Context(), actor(r), auditPcapUpload, id.String(),
		map[string]any{"name": sanitizeName(r.FormValue("name")), "size": size})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "size": size, "sha256": sum})
}

// pcapView 是对外的 pcap 视图：不暴露容器内 stored_path（错误/响应不泄露内部路径）。
type pcapView struct {
	ID           string     `json:"id"`
	OriginalName string     `json:"original_name"`
	SizeBytes    int64      `json:"size_bytes"`
	PacketCount  *int64     `json:"packet_count"`
	Sha256       *string    `json:"sha256"`
	SampleType   string     `json:"sample_type"`
	CreatedAt    *time.Time `json:"created_at"`
}

func toPcapView(p gen.Pcap) pcapView {
	v := pcapView{ID: p.ID, OriginalName: p.OriginalName, SizeBytes: p.SizeBytes, SampleType: p.SampleType}
	if p.PacketCount.Valid {
		n := p.PacketCount.Int64
		v.PacketCount = &n
	}
	if p.Sha256.Valid {
		h := p.Sha256.String
		v.Sha256 = &h
	}
	if p.CreatedAt.Valid {
		t := p.CreatedAt.Time
		v.CreatedAt = &t
	}
	return v
}

// parsePageParams 解析 limit/offset：limit 默认 50、上限 200，offset 非负。
func parsePageParams(q url.Values) (limit, offset int32, err error) {
	limit = 50
	if s := q.Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 200 {
			return 0, 0, fmt.Errorf("limit must be 1..200")
		}
		limit = int32(n)
	}
	if s := q.Get("offset"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 0 || n > 1_000_000 {
			return 0, 0, fmt.Errorf("offset must be 0..1000000")
		}
		offset = int32(n)
	}
	return limit, offset, nil
}

// handleListPcaps 架构设计 §6.3 GET /pcaps（viewer+）。
func (s *Server) handleListPcaps(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parsePageParams(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := gen.New(s.pool).ListPcaps(r.Context(), gen.ListPcapsParams{Limit: limit, Offset: offset})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db query failed")
		return
	}
	items := make([]pcapView, 0, len(rows))
	for _, p := range rows {
		items = append(items, toPcapView(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

// handleCreateTask 创建回放任务并入队（Redis 唤醒，PG 是真相）。
func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PcapID string `json:"pcap_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	pcapID, err := uuid.Parse(req.PcapID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "pcap_id must be uuid")
		return
	}
	q := gen.New(s.pool)
	if _, err := q.GetPcap(r.Context(), pcapID.String()); err != nil {
		writeErr(w, http.StatusNotFound, "pcap not found")
		return
	}
	taskID := uuid.New()
	if err := q.CreateTask(r.Context(), gen.CreateTaskParams{ID: taskID.String(), PcapID: pcapID.String()}); err != nil {
		writeErr(w, http.StatusInternalServerError, "db insert failed")
		return
	}
	if err := s.rdb.LPush(r.Context(), replayQueue, taskID.String()).Err(); err != nil {
		writeErr(w, http.StatusInternalServerError, "queue push failed")
		return
	}
	s.audit(r.Context(), actor(r), auditTaskCreate, taskID.String(), map[string]any{"pcap_id": pcapID.String()})
	writeJSON(w, http.StatusCreated, map[string]string{"id": taskID.String(), "status": "queued"})
}

// alertSortKeys 前端排序字段 → SQL CASE 分支键的白名单；不在表内的一律 400，不透传（M7）。
var alertSortKeys = map[string]string{
	"ts":       "ts",
	"severity": "severity",
	"sid":      "sid",
	"src_ip":   "src_ip",
	"dest_ip":  "dest_ip",
}

// alertProtos 大写输入 → eve.json 中的规范写法
var alertProtos = map[string]string{"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP", "IPV6-ICMP": "IPv6-ICMP", "SCTP": "SCTP"}

// parseAlertQuery 把查询串校验并映射为 sqlc 参数；纯函数，便于表驱动测试。
func parseAlertQuery(v url.Values) (gen.ListAlertsParams, error) {
	p := gen.ListAlertsParams{SortKey: "ts", SortDesc: true, PageLimit: 50}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 || n > 500 {
			return p, errors.New("limit must be 1..500")
		}
		p.PageLimit = int32(n)
	}
	if s := v.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return p, errors.New("offset must be >= 0")
		}
		p.PageOffset = int32(n)
	}
	if s := v.Get("sort"); s != "" {
		key, ok := alertSortKeys[s]
		if !ok {
			return p, errors.New("sort must be one of ts|severity|sid|src_ip|dest_ip")
		}
		p.SortKey = key
	}
	switch v.Get("order") {
	case "", "desc":
	case "asc":
		p.SortDesc = false
	default:
		return p, errors.New("order must be asc|desc")
	}
	if s := v.Get("task_id"); s != "" {
		if _, err := uuid.Parse(s); err != nil {
			return p, errors.New("task_id must be uuid")
		}
		p.TaskID = &s
	}
	if s := v.Get("sid"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return p, errors.New("sid must be positive int")
		}
		p.Sid = pgtype.Int8{Int64: n, Valid: true}
	}
	for _, f := range []struct {
		key string
		dst *pgtype.Text
	}{{"src_ip", &p.SrcIp}, {"dest_ip", &p.DestIp}} {
		if s := v.Get(f.key); s != "" {
			if net.ParseIP(s) == nil {
				return p, fmt.Errorf("%s must be an IP address", f.key)
			}
			*f.dst = pgtype.Text{String: s, Valid: true}
		}
	}
	if s := v.Get("severity"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 4 {
			return p, errors.New("severity must be 1..4")
		}
		p.Severity = pgtype.Int4{Int32: int32(n), Valid: true}
	}
	if s := v.Get("proto"); s != "" {
		canon, ok := alertProtos[strings.ToUpper(s)]
		if !ok {
			return p, errors.New("proto must be TCP|UDP|ICMP|IPv6-ICMP|SCTP")
		}
		p.Proto = pgtype.Text{String: canon, Valid: true}
	}
	if s := v.Get("status"); s != "" {
		if !validGroupStatus[s] {
			return p, errors.New("status must be new|confirmed|false_positive|ignored")
		}
		p.TriageStatus = pgtype.Text{String: s, Valid: true}
	}
	for _, f := range []struct {
		key string
		dst *pgtype.Timestamptz
	}{{"from", &p.TsFrom}, {"to", &p.TsTo}} {
		if s := v.Get(f.key); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return p, fmt.Errorf("%s must be RFC3339", f.key)
			}
			*f.dst = pgtype.Timestamptz{Time: t, Valid: true}
		}
	}
	if p.TsFrom.Valid && p.TsTo.Valid && p.TsTo.Time.Before(p.TsFrom.Time) {
		return p, errors.New("to must not be before from")
	}
	return p, nil
}

// handleListAlerts 告警列表：服务端过滤 + 白名单排序 + 分页（M4/M7）。
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	params, err := parseAlertQuery(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	q := gen.New(s.pool)
	rows, err := q.ListAlerts(r.Context(), params)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	total, err := q.CountAlerts(r.Context(), gen.CountAlertsParams{
		TaskID:       params.TaskID,
		Sid:          params.Sid,
		SrcIp:        params.SrcIp,
		DestIp:       params.DestIp,
		Severity:     params.Severity,
		Proto:        params.Proto,
		TriageStatus: params.TriageStatus,
		TsFrom:       params.TsFrom,
		TsTo:         params.TsTo,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []gen.ListAlertsRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": rows})
}

// handleGetAlert 告警详情：含关联 flow（M4 详情要求）。
func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	q := gen.New(s.pool)
	alert, err := q.GetAlert(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "alert not found")
		return
	}
	resp := map[string]any{"alert": alert}
	if alert.FlowID.Valid {
		if flow, err := q.GetFlow(r.Context(), gen.GetFlowParams{
			TaskID: alert.TaskID, FlowID: alert.FlowID.Int64,
		}); err == nil {
			resp["flow"] = flow
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleListTasks / handleGetTask 回放任务查询。
func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	rows, err := gen.New(s.pool).ListTasks(r.Context(), gen.ListTasksParams{Limit: limit, Offset: offset})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []gen.ListTasksRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	task, err := gen.New(s.pool).GetTask(r.Context(), id.String())
	if err != nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, task)
}

var errNotFound = errors.New("not found")

// ---- helpers ----

func isPcapMagic(m []byte) bool {
	switch {
	case m[0] == 0xa1 && m[1] == 0xb2 && m[2] == 0xc3 && m[3] == 0xd4,
		m[0] == 0xd4 && m[1] == 0xc3 && m[2] == 0xb2 && m[3] == 0xa1,
		m[0] == 0xa1 && m[1] == 0xb2 && m[2] == 0x3c && m[3] == 0x4d,
		m[0] == 0x4d && m[1] == 0x3c && m[2] == 0xb2 && m[3] == 0xa1,
		m[0] == 0x0a && m[1] == 0x0d && m[2] == 0x0d && m[3] == 0x0a:
		return true
	}
	return false
}

func sanitizeName(name string) string {
	if name == "" {
		return "unnamed.pcap"
	}
	// 只保留文件名部分，剥掉任何路径成分
	return filepath.Base(name)
}

func pageParams(r *http.Request) (limit, offset int32) {
	limit = 50
	offset = 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = int32(v)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = int32(v)
	}
	return limit, offset
}

var _ = redis.Nil // 保留 redis 引用（队列在 handleCreateTask 使用）
