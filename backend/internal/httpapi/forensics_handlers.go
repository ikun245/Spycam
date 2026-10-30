package httpapi

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"spycam/backend/internal/live"
	"spycam/backend/internal/pcapslice"
	"spycam/backend/internal/store/gen"
)

// 取证时间窗：阈值类规则在第 N 个包才告警，故向前多取；向后留出会话收尾。
const (
	forensicsBefore = 5 * time.Minute
	forensicsAfter  = time.Minute
)

var protoNumbers = map[string]uint8{"TCP": 6, "UDP": 17, "ICMP": 1, "IPV6-ICMP": 58, "SCTP": 132}

// parseInetAddr 兼容 PostgreSQL inet 文本可能带的前缀长度（如 "10.0.0.1/32"）。
func parseInetAddr(s string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// alertTuple 是构造切片条件所需的告警字段子集，与具体 sqlc 行类型解耦。
type alertTuple struct {
	Ts                pgtype.Timestamptz
	SrcIp, DestIp     string
	SrcPort, DestPort pgtype.Int4
	Proto             pgtype.Text
}

// buildForensicsFilter 由告警构造切片条件；scope 只接受白名单值：
// flow（默认，双向五元组）或 hosts（仅 IP 对 + 协议，适合扫描类告警——每个探测包源端口不同）。
func buildForensicsFilter(a alertTuple, scope string) (pcapslice.Filter, error) {
	var f pcapslice.Filter
	if !a.Ts.Valid {
		return f, errors.New("alert has no timestamp")
	}
	src, err := parseInetAddr(a.SrcIp)
	if err != nil {
		return f, fmt.Errorf("bad src ip: %w", err)
	}
	dst, err := parseInetAddr(a.DestIp)
	if err != nil {
		return f, fmt.Errorf("bad dest ip: %w", err)
	}
	f.A, f.B = src, dst
	f.Proto = protoNumbers[strings.ToUpper(a.Proto.String)]
	f.From, f.To = a.Ts.Time.Add(-forensicsBefore), a.Ts.Time.Add(forensicsAfter)
	switch scope {
	case "", "flow":
		if a.SrcPort.Valid && a.SrcPort.Int32 > 0 && a.SrcPort.Int32 <= 65535 {
			f.PortA = uint16(a.SrcPort.Int32)
		}
		if a.DestPort.Valid && a.DestPort.Int32 > 0 && a.DestPort.Int32 <= 65535 {
			f.PortB = uint16(a.DestPort.Int32)
		}
	case "hosts":
	default:
		return f, errors.New("scope must be flow or hosts")
	}
	return f, nil
}

// handleExportAlertPcap 告警取证（S4）：按告警时间窗 + 五元组从原 pcap 切出相关报文并下载。
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
	scope := r.URL.Query().Get("scope")
	flt, err := buildForensicsFilter(alertTuple{
		Ts: alert.Ts, SrcIp: alert.SrcIp, DestIp: alert.DestIp,
		SrcPort: alert.SrcPort, DestPort: alert.DestPort, Proto: alert.Proto,
	}, scope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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
	if pcap.SampleType == live.SampleType {
		// 在线抓包不落全量包（题面明确排除全量存包），没有可切片的原始文件
		writeErr(w, http.StatusConflict, "live capture alerts have no stored pcap")
		return
	}

	// 用 UUID 拼路径，不使用数据库里的 stored_path（避免历史脏数据造成越权读）
	src := filepath.Join(s.cfg.PcapsDir, pcap.ID+".pcap")
	in, err := os.Open(src)
	if err != nil {
		writeErr(w, http.StatusNotFound, "source pcap file missing")
		return
	}
	defer in.Close()

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("X-Filter-Time", fmt.Sprintf("%s/%s",
		flt.From.UTC().Format(time.RFC3339), flt.To.UTC().Format(time.RFC3339)))
	w.Header().Set("X-Filter-Tuple", fmt.Sprintf("%s:%d<->%s:%d/%s",
		flt.A, flt.PortA, flt.B, flt.PortB, alert.Proto.String))

	// 先切到内存（输入已限 64MB）再写响应，切片失败时还能返回正确的错误码
	var out bytes.Buffer
	res, err := pcapslice.Slice(in, &out, flt)
	switch {
	case errors.Is(err, pcapslice.ErrUnsupported):
		// pcapng 等格式无法切片：如实声明后回传原文件
		w.Header().Set("X-Filter-Applied", "false")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="alert-%d-%s-full.pcap"`, alert.ID, pcap.ID[:8]))
		if _, serr := in.Seek(0, 0); serr != nil {
			writeErr(w, http.StatusInternalServerError, "rewind failed")
			return
		}
		http.ServeContent(w, r, "", time.Time{}, in)
		return
	case err != nil:
		slog.Warn("pcap slice failed", "alert_id", alert.ID, "pcap_id", pcap.ID, "err", err)
		writeErr(w, http.StatusUnprocessableEntity, "source pcap is malformed")
		return
	}
	s.audit(r.Context(), actor(r), auditPcapExport, strconv.FormatInt(alert.ID, 10),
		map[string]any{"scope": scopeOrDefault(scope), "matched": res.Matched, "total": res.Total})
	w.Header().Set("X-Filter-Applied", "true")
	w.Header().Set("X-Packets-Matched", strconv.Itoa(res.Matched))
	w.Header().Set("X-Packets-Total", strconv.Itoa(res.Total))
	if res.Truncated {
		w.Header().Set("X-Source-Truncated", "true")
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="alert-%d-%s.pcap"`, alert.ID, pcap.ID[:8]))
	w.Header().Set("Content-Length", strconv.Itoa(out.Len()))
	_, _ = w.Write(out.Bytes())
}

func scopeOrDefault(s string) string {
	if s == "" {
		return "flow"
	}
	return s
}
