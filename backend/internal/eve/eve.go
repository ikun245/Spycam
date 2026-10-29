// Package eve 解析 Suricata eve.json 事件并归一化为入库结构（架构设计 §6.4）。
package eve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Event 是 eve.json 单行的宽松解析结果；只提取入库需要的字段，原文整体保留。
// Timestamp 由 Parse 单独解析后赋值，json:"-" 避免二次 Unmarshal 撞非 RFC3339 格式。
type Event struct {
	Timestamp time.Time        `json:"-"`
	EventType   string           `json:"event_type"`
	FlowID      *int64           `json:"flow_id"`
	CommunityID string           `json:"community_id"`
	SrcIP       string           `json:"src_ip"`
	SrcPort     *int             `json:"src_port"`
	DestIP      string           `json:"dest_ip"`
	DestPort    *int             `json:"dest_port"`
	Proto       string           `json:"proto"`
	AppProto    *string          `json:"app_proto"`

	Alert *Alert `json:"alert,omitempty"`
	Flow  *Flow  `json:"flow,omitempty"`
	DNS   *DNS   `json:"dns,omitempty"`
	HTTP  *HTTP  `json:"http,omitempty"`
	TLS   *TLS   `json:"tls,omitempty"`
	Stats *Stats `json:"stats,omitempty"`

	Raw json.RawMessage `json:"-"`
}

// Alert 对应 eve 的 alert 对象。
type Alert struct {
	SignatureID      int64  `json:"signature_id"`
	Signature        string `json:"signature"`
	Severity         *int   `json:"severity"`
	Category         string `json:"category"`
	PayloadPrintable string `json:"payload_printable"`
}

// Flow 是流统计摘要（flow 事件或 alert 携带的 flow 字段）。
type Flow struct {
	PktsToserver  *int64 `json:"pkts_toserver"`
	BytesToserver *int64 `json:"bytes_toserver"`
	PktsToclient  *int64 `json:"pkts_toclient"`
	BytesToclient *int64 `json:"bytes_toclient"`
	State         string `json:"state"`
}

// DNS 是 dns 事件关键字段。
type DNS struct {
	Type   string `json:"type"`
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	RCode  string `json:"rcode"`
}

// HTTP 是 http 事件关键字段。
type HTTP struct {
	Hostname   string `json:"hostname"`
	URL        string `json:"url"`
	HTTPMethod string `json:"http_method"`
	Status     *int   `json:"status"`
	UserAgent  string `json:"user_agent"`
}

// TLS 是 tls 事件关键字段。
type TLS struct {
	SNI     string `json:"sni"`
	Version string `json:"version"`
}

// Stats 是引擎周期统计事件（S6 可观测），字段按 Suricata 7 eve stats 实际结构映射：
// detect.alert（累计告警）、detect.engines[].rules_loaded/rules_failed、capture.kernel_drops。
// 离线 pcap-file 模式没有 capture 段，故用指针区分“未上报”与“0 丢包”。
type Stats struct {
	Uptime int64 `json:"uptime"`
	Detect struct {
		Alert   *int64 `json:"alert"`
		Engines []struct {
			RulesLoaded int64 `json:"rules_loaded"`
			RulesFailed int64 `json:"rules_failed"`
		} `json:"engines"`
	} `json:"detect"`
	Capture *struct {
		KernelDrops *int64 `json:"kernel_drops"`
	} `json:"capture"`
}

// RulesLoaded 汇总各检测引擎已加载规则数；未上报 engines 时返回 nil。
func (s *Stats) RulesLoaded() (loaded, failed *int64) {
	if len(s.Detect.Engines) == 0 {
		return nil, nil
	}
	var l, f int64
	for _, e := range s.Detect.Engines {
		l += e.RulesLoaded
		f += e.RulesFailed
	}
	return &l, &f
}

// KernelDrops 返回内核丢包数；pcap-file 模式无 capture 段时返回 nil。
func (s *Stats) KernelDrops() *int64 {
	if s.Capture == nil {
		return nil
	}
	return s.Capture.KernelDrops
}

// Parse 解析单行 eve.json；解析失败返回错误由调用方计数跳过。
func Parse(line []byte) (*Event, error) {
	// 先单独提取 timestamp（Suricata 格式：2006-01-02T15:04:05.999999+0000，非 RFC3339）
	var tsProbe struct {
		EventType string `json:"event_type"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(line, &tsProbe); err != nil {
		return nil, fmt.Errorf("decode eve line: %w", err)
	}
	if tsProbe.EventType == "" || tsProbe.Timestamp == "" {
		return nil, fmt.Errorf("missing event_type/timestamp")
	}
	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", tsProbe.Timestamp)
	if err != nil {
		if ts, err = time.Parse(time.RFC3339Nano, tsProbe.Timestamp); err != nil {
			return nil, fmt.Errorf("parse timestamp %q: %w", tsProbe.Timestamp, err)
		}
	}

	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, fmt.Errorf("decode eve line: %w", err)
	}
	ev.Timestamp = ts.UTC()
	ev.Raw = json.RawMessage(line)
	return &ev, nil
}

// DedupKey 生成事件幂等键：flow_id + 纳秒时间戳 + 类型 + sid（告警）。
// 同一行重复消费会得到相同 key，靠 alerts 的 UNIQUE 约束去重。
func (e *Event) DedupKey() string {
	var flowID int64
	if e.FlowID != nil {
		flowID = *e.FlowID
	}
	var sid int64
	if e.Alert != nil {
		sid = e.Alert.SignatureID
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s|%d", flowID, e.Timestamp.UnixNano(), e.EventType, sid)))
	return hex.EncodeToString(sum[:16])
}
