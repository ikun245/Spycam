package eve

import (
	"testing"
	"time"
)

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantUTC string
		wantErr bool
	}{
		{
			name:    "suricata 数字时区格式",
			line:    `{"timestamp":"2026-10-29T08:25:33.839932+0000","event_type":"flow"}`,
			wantUTC: "2026-10-29T08:25:33.839932Z",
		},
		{
			name:    "非零时区偏移",
			line:    `{"timestamp":"2025-12-29T09:20:00.000000+0800","event_type":"alert"}`,
			wantUTC: "2025-12-29T01:20:00Z",
		},
		{
			name:    "RFC3339 兼容格式",
			line:    `{"timestamp":"2026-01-01T00:00:00Z","event_type":"flow"}`,
			wantUTC: "2026-01-01T00:00:00Z",
		},
		{
			name:    "缺 timestamp 报错",
			line:    `{"event_type":"flow"}`,
			wantErr: true,
		},
		{
			name:    "缺 event_type 报错",
			line:    `{"timestamp":"2026-01-01T00:00:00Z"}`,
			wantErr: true,
		},
		{
			name:    "非法 JSON 报错",
			line:    `{not-json`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := Parse([]byte(tt.line))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := ev.Timestamp.UTC().Format(time.RFC3339Nano); got != tt.wantUTC {
				t.Errorf("timestamp = %q, want %q", got, tt.wantUTC)
			}
		})
	}
}

func TestParseAlertEvent(t *testing.T) {
	line := []byte(`{"timestamp":"2026-01-01T00:00:05.123456+0000","flow_id":12345,` +
		`"event_type":"alert","src_ip":"10.0.0.66","src_port":51000,` +
		`"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","app_proto":"http",` +
		`"alert":{"signature_id":1000003,"signature":"SPYCAM SQLi","severity":2,` +
		`"category":"web-application-attack","payload_printable":"GET /x HTTP/1.1"}}`)

	ev, err := Parse(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.EventType != "alert" || ev.Alert == nil {
		t.Fatalf("expected alert event")
	}
	if ev.Alert.SignatureID != 1000003 {
		t.Errorf("sid = %d", ev.Alert.SignatureID)
	}
	if ev.FlowID == nil || *ev.FlowID != 12345 {
		t.Errorf("flow_id = %v", ev.FlowID)
	}
	if ev.DestPort == nil || *ev.DestPort != 80 {
		t.Errorf("dest_port = %v", ev.DestPort)
	}
	if ev.Alert.PayloadPrintable != "GET /x HTTP/1.1" {
		t.Errorf("payload = %q", ev.Alert.PayloadPrintable)
	}
}

func TestDedupKeyStableAndDistinct(t *testing.T) {
	line := `{"timestamp":"2026-01-01T00:00:05.000000+0000","flow_id":7,"event_type":"alert"}`
	ev1, _ := Parse([]byte(line))
	ev2, _ := Parse([]byte(line))
	if ev1.DedupKey() != ev2.DedupKey() {
		t.Fatalf("same event must produce same dedup key")
	}

	other := `{"timestamp":"2026-01-01T00:00:05.000000+0000","flow_id":8,"event_type":"alert"}`
	ev3, _ := Parse([]byte(other))
	if ev1.DedupKey() == ev3.DedupKey() {
		t.Fatalf("different flow_id must produce different key")
	}
}

func TestParseStatsEvent(t *testing.T) {
	// 结构取自 Suricata 7 pcap-file 模式真实 stats 事件（无 capture 段）
	pcapMode := `{"timestamp":"2026-10-29T08:00:10.000000+0000","event_type":"stats","stats":{"uptime":42,` +
		`"decoder":{"pkts":1200},"detect":{"engines":[{"id":0,"last_reload":"2026-10-29T08:00:00.000000+0000",` +
		`"rules_loaded":36,"rules_failed":1,"rules_skipped":0}],"alert":17,"alerts_suppressed":0}}}`
	ev, err := Parse([]byte(pcapMode))
	if err != nil || ev.Stats == nil {
		t.Fatalf("parse stats: %v", err)
	}
	if ev.Stats.Uptime != 42 {
		t.Errorf("uptime = %d", ev.Stats.Uptime)
	}
	if ev.Stats.Detect.Alert == nil || *ev.Stats.Detect.Alert != 17 {
		t.Errorf("detect.alert = %v", ev.Stats.Detect.Alert)
	}
	loaded, failed := ev.Stats.RulesLoaded()
	if loaded == nil || *loaded != 36 || failed == nil || *failed != 1 {
		t.Errorf("rules loaded/failed = %v/%v", loaded, failed)
	}
	if ev.Stats.KernelDrops() != nil {
		t.Errorf("pcap 模式无 capture 段，kernel_drops 应为 nil（未上报），不能当成 0")
	}

	liveMode := `{"timestamp":"2026-10-29T08:00:10+0000","event_type":"stats","stats":{"uptime":5,` +
		`"capture":{"kernel_packets":900,"kernel_drops":3}}}`
	ev, err = Parse([]byte(liveMode))
	if err != nil || ev.Stats == nil {
		t.Fatalf("parse live stats: %v", err)
	}
	if d := ev.Stats.KernelDrops(); d == nil || *d != 3 {
		t.Errorf("kernel_drops = %v", d)
	}
	if l, f := ev.Stats.RulesLoaded(); l != nil || f != nil {
		t.Errorf("无 engines 段时应返回 nil，got %v/%v", l, f)
	}
}
