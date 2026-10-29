// Package ingest 读取任务输出目录中的 eve.json，解析后批量写入 PostgreSQL（架构设计 §6.4）。
package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"spycam/backend/internal/eve"
	"spycam/backend/internal/store/gen"
)

// Result 是一次采集的统计。
type Result struct {
	Events  int64
	Alerts  int64
	Skipped int64
}

// IngestTask 把任务输出目录里的全部 eve.json 采集入库（幂等，可重复调用）。
func IngestTask(ctx context.Context, pool *pgxpool.Pool, taskID, dir string) (Result, error) {
	var res Result
	if _, err := os.Stat(dir); err != nil {
		return res, fmt.Errorf("eve dir %s: %w", dir, err)
	}
	q := gen.New(pool)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return res, fmt.Errorf("read dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		n, err := ingestFile(ctx, q, taskID, filepath.Join(dir, entry.Name()))
		if err != nil {
			return res, fmt.Errorf("ingest %s: %w", entry.Name(), err)
		}
		res.Events += n.Events
		res.Alerts += n.Alerts
		res.Skipped += n.Skipped
	}
	slog.Info("ingest done", "task_id", taskID, "events", res.Events,
		"alerts", res.Alerts, "skipped", res.Skipped)
	return res, nil
}

func ingestFile(ctx context.Context, q *gen.Queries, taskID, path string) (Result, error) {
	var res Result
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := readLine(reader)
		if len(line) > 0 {
			res.Events++
			if perr := processLine(ctx, q, taskID, line); perr != nil {
				res.Skipped++
				slog.Warn("eve line skipped", "task_id", taskID, "err", perr)
			} else if isAlert(line) {
				res.Alerts++
			}
		}
		if err != nil {
			if err == io.EOF {
				return res, nil
			}
			return res, err
		}
	}
}

// readLine 兼容超长行（payload 大时单行可超过默认 buffer）。
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		out = append(out, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return trimEOL(out), err
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func isAlert(line []byte) bool {
	for i := 0; i+16 <= len(line); i++ {
		if string(line[i:i+16]) == `"event_type":"al` {
			return true
		}
	}
	return false
}

func processLine(ctx context.Context, q *gen.Queries, taskID string, line []byte) error {
	ev, err := eve.Parse(line)
	if err != nil {
		return err
	}
	ts := pgtype.Timestamptz{Time: ev.Timestamp, Valid: !ev.Timestamp.IsZero()}
	switch ev.EventType {
	case "alert":
		a := ev.Alert
		if a == nil {
			return fmt.Errorf("alert event without alert object")
		}
		sev := pgtype.Int4{}
		if a.Severity != nil {
			sev = pgtype.Int4{Int32: int32(*a.Severity), Valid: true}
		}
		return q.CreateAlert(ctx, gen.CreateAlertParams{
			TaskID:           taskID,
			Ts:               ts,
			FlowID:           int8Ptr(ev.FlowID),
			CommunityID:      textPtr(strOrNil(ev.CommunityID)),
			SrcIp:            orEmpty(ev.SrcIP),
			SrcPort:          int4Ptr(ev.SrcPort),
			DestIp:           orEmpty(ev.DestIP),
			DestPort:         int4Ptr(ev.DestPort),
			Proto:            textPtr(strOrNil(ev.Proto)),
			AppProto:         textPtr(ev.AppProto),
			Sid:              a.SignatureID,
			Signature:        textPtr(strOrNil(a.Signature)),
			Severity:         sev,
			Category:         textPtr(strOrNil(a.Category)),
			PayloadPrintable: textPtr(strOrNil(a.PayloadPrintable)),
			Raw:              line,
			DedupKey:         ev.DedupKey(),
		})
	case "flow":
		fl := ev.Flow
		if fl == nil || ev.FlowID == nil {
			return nil // 缺关键字段的事件不落 flow 表
		}
		return q.UpsertFlow(ctx, gen.UpsertFlowParams{
			FlowID:        *ev.FlowID,
			TaskID:        taskID,
			SrcIp:         orEmpty(ev.SrcIP),
			SrcPort:       int4Ptr(ev.SrcPort),
			DestIp:        orEmpty(ev.DestIP),
			DestPort:      int4Ptr(ev.DestPort),
			Proto:         textPtr(strOrNil(ev.Proto)),
			AppProto:      textPtr(ev.AppProto),
			PktsToserver:  int8Ptr(fl.PktsToserver),
			BytesToserver: int8Ptr(fl.BytesToserver),
			PktsToclient:  int8Ptr(fl.PktsToclient),
			BytesToclient: int8Ptr(fl.BytesToclient),
			State:         textPtr(strOrNil(fl.State)),
			StartTs:       ts,
			EndTs:         ts,
		})
	case "dns":
		if ev.DNS == nil {
			return nil
		}
		return q.CreateDnsEvent(ctx, gen.CreateDnsEventParams{
			TaskID:  taskID,
			FlowID:  int8Ptr(ev.FlowID),
			Ts:      ts,
			SrcIp:   textPtr(strOrNil(ev.SrcIP)),
			DestIp:  textPtr(strOrNil(ev.DestIP)),
			DnsType: textPtr(strOrNil(ev.DNS.Type)),
			Qname:   textPtr(strOrNil(ev.DNS.RRName)),
			Rrtype:  textPtr(strOrNil(ev.DNS.RRType)),
			Rcode:   textPtr(strOrNil(ev.DNS.RCode)),
			Raw:     line,
		})
	case "http":
		if ev.HTTP == nil {
			return nil
		}
		return q.CreateHttpEvent(ctx, gen.CreateHttpEventParams{
			TaskID:       taskID,
			FlowID:       int8Ptr(ev.FlowID),
			Ts:           ts,
			SrcIp:        textPtr(strOrNil(ev.SrcIP)),
			DestIp:       textPtr(strOrNil(ev.DestIP)),
			DestPort:     int4Ptr(ev.DestPort),
			Hostname:     textPtr(strOrNil(ev.HTTP.Hostname)),
			HttpUri:      textPtr(strOrNil(ev.HTTP.URL)),
			HttpMethod:   textPtr(strOrNil(ev.HTTP.HTTPMethod)),
			HttpStatus:   int4Ptr(ev.HTTP.Status),
			HttpUserAgent: textPtr(strOrNil(ev.HTTP.UserAgent)),
			Raw:          line,
		})
	case "tls":
		if ev.TLS == nil {
			return nil
		}
		return q.CreateTlsEvent(ctx, gen.CreateTlsEventParams{
			TaskID:   taskID,
			FlowID:   int8Ptr(ev.FlowID),
			Ts:       ts,
			SrcIp:    textPtr(strOrNil(ev.SrcIP)),
			DestIp:   textPtr(strOrNil(ev.DestIP)),
			DestPort: int4Ptr(ev.DestPort),
			Sni:      textPtr(strOrNil(ev.TLS.SNI)),
			Version:  textPtr(strOrNil(ev.TLS.Version)),
			Raw:      line,
		})
	case "stats":
		// S6 引擎可观测：周期性 stats 事件写 engine_stats（最新一条供前端读取）
		if ev.Stats == nil {
			return nil
		}
		loaded, failed := ev.Stats.RulesLoaded()
		// rule_load_ms 不在 stats 事件里，由 engine-agent 记录最近一次校验+重载耗时
		return q.CreateEngineStat(ctx, gen.CreateEngineStatParams{
			Ts:          ts,
			UptimeSec:   int8Ptr(&ev.Stats.Uptime),
			RulesLoaded: int8Ptr(loaded),
			KernelDrops: int8Ptr(ev.Stats.KernelDrops()),
			AlertsTotal: int8Ptr(ev.Stats.Detect.Alert),
			RulesFailed: int8Ptr(failed),
		})
	default:
		return nil // 其余类型只计数
	}
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orEmpty(s string) string {
	if s == "" {
		return "0.0.0.0"
	}
	return s
}

func textPtr(v any) pgtype.Text {
	if s, ok := v.(string); ok && s != "" {
		return pgtype.Text{String: s, Valid: true}
	}
	return pgtype.Text{}
}

func int4Ptr(p *int) pgtype.Int4 {
	if p == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(*p), Valid: true}
}

func int8Ptr(p *int64) pgtype.Int8 {
	if p == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *p, Valid: true}
}

// WaitDir 等待目录出现（回放刚提交时输出目录可能尚未创建）。
func WaitDir(ctx context.Context, dir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("dir %s not created within %s", dir, timeout)
}

// MarshalProgress 输出采集进度的 JSON 摘要（日志用）。
func MarshalProgress(r Result) string {
	b, _ := json.Marshal(r)
	return string(b)
}
