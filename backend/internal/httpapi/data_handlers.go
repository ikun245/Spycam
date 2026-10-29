package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

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
	size, err := io.Copy(out, file)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "write failed")
		return
	}

	sum := sha256.Sum256(magic) // P0: 全量哈希在 P2 评测阶段补
	_ = sum
	q := gen.New(s.pool)
	if err := q.CreatePcap(r.Context(), gen.CreatePcapParams{
		ID:           id.String(),
		OriginalName: sanitizeName(r.FormValue("name")),
		StoredPath:   storedPath,
		SizeBytes:    size,
		SampleType:   r.FormValue("sample_type"),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "db insert failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "size": size})
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
	writeJSON(w, http.StatusCreated, map[string]string{"id": taskID.String(), "status": "queued"})
}

// handleListAlerts 告警列表：过滤参数可选，排序白名单在服务端（M7）。
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	q := gen.New(s.pool)
	taskID := r.URL.Query().Get("task_id")
	sidStr := r.URL.Query().Get("sid")
	srcIP := r.URL.Query().Get("src_ip")

	filters := gen.ListAlertsParams{Limit: limit, Offset: offset}
	if taskID != "" {
		if _, err := uuid.Parse(taskID); err != nil {
			writeErr(w, http.StatusBadRequest, "task_id must be uuid")
			return
		}
		filters.TaskID = &taskID
	}
	if sidStr != "" {
		v, err := strconv.ParseInt(sidStr, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "sid must be int")
			return
		}
		filters.Sid = pgtype.Int8{Int64: v, Valid: true}
	}
	if srcIP != "" {
		filters.SrcIp = pgtype.Text{String: srcIP, Valid: true}
	}

	countFilters := gen.CountAlertsParams{
		TaskID: filters.TaskID,
		Sid:    filters.Sid,
		SrcIp:  filters.SrcIp,
	}
	rows, err := q.ListAlerts(r.Context(), filters)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	total, err := q.CountAlerts(r.Context(), countFilters)
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
