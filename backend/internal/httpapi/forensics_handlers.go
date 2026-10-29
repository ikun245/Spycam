package httpapi

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"spycam/backend/internal/store/gen"
)

// handleExportAlertPcap 告警取证（S4）：按告警时间戳 + 五元组从原 pcap 提取片段并下载。
// 只读取服务端已存 pcap，路径用数据库 UUID 重新拼接，不接受调用方路径（M7 防穿越）。
func (s *Server) handleExportAlertPcap(w http.ResponseWriter, r *http.Request) {
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
	task, err := q.GetTask(r.Context(), alert.TaskID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	pcap, err := q.GetPcap(r.Context(), task.PcapID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "source pcap not found")
		return
	}

	// 用 UUID 拼路径，不使用数据库里的 stored_path（避免历史脏数据造成越权读）
	src := filepath.Join(s.cfg.PcapsDir, pcap.ID+".pcap")
	if st, err := os.Stat(src); err != nil || st.IsDir() {
		writeErr(w, http.StatusNotFound, "source pcap file missing")
		return
	}

	// 简化实现：按时间窗/五元组过滤需逐包解析；当前回传整段 pcap，
	// 响应头声明过滤条件，完整切片为已知缺陷（见 README）。
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="alert-%d-%s.pcap"`, alert.ID, pcap.ID[:8]))
	w.Header().Set("X-Filter-Time", alert.Ts.Time.UTC().Format("2006-01-02T15:04:05Z07:00"))
	w.Header().Set("X-Filter-Tuple", fmt.Sprintf("%s:%d-%s:%d/%s",
		alert.SrcIp, alert.SrcPort.Int32, alert.DestIp, alert.DestPort.Int32, alert.Proto.String))
	http.ServeFile(w, r, src)
}
