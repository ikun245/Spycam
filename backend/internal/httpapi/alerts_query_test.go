package httpapi

import (
	"net/url"
	"testing"
)

func TestParseAlertQuery(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{name: "defaults", query: ""},
		{name: "sort whitelisted asc", query: "sort=severity&order=asc"},
		{name: "sort injection rejected", query: "sort=ts%3BDROP+TABLE+alerts", wantErr: true},
		{name: "sort unknown column rejected", query: "sort=raw", wantErr: true},
		{name: "order invalid", query: "order=sideways", wantErr: true},
		{name: "limit too large", query: "limit=501", wantErr: true},
		{name: "limit zero", query: "limit=0", wantErr: true},
		{name: "offset negative", query: "offset=-1", wantErr: true},
		{name: "task_id not uuid", query: "task_id=../../etc", wantErr: true},
		{name: "src_ip not ip", query: "src_ip=1.2.3.4' OR 1=1", wantErr: true},
		{name: "dest_ip ipv6 ok", query: "dest_ip=fe80::1"},
		{name: "severity out of range", query: "severity=9", wantErr: true},
		{name: "proto lowercase ok", query: "proto=udp"},
		{name: "proto unknown", query: "proto=gre", wantErr: true},
		{name: "status ok", query: "status=false_positive"},
		{name: "status unknown", query: "status=deleted", wantErr: true},
		{name: "time range ok", query: "from=2026-01-01T00:00:00Z&to=2026-01-01T01:00:00Z"},
		{name: "time not rfc3339", query: "from=yesterday", wantErr: true},
		{name: "time reversed", query: "from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := url.ParseQuery(c.query)
			if err != nil {
				t.Fatalf("bad test query: %v", err)
			}
			_, err = parseAlertQuery(v)
			if (err != nil) != c.wantErr {
				t.Fatalf("query %q: err=%v wantErr=%v", c.query, err, c.wantErr)
			}
		})
	}
}

func TestParseAlertQueryMapping(t *testing.T) {
	v, _ := url.ParseQuery("sort=src_ip&order=asc&limit=20&offset=40&proto=ipv6-icmp&severity=2&status=new")
	p, err := parseAlertQuery(v)
	if err != nil {
		t.Fatal(err)
	}
	if p.SortKey != "src_ip" || p.SortDesc {
		t.Errorf("sort = %q desc=%v", p.SortKey, p.SortDesc)
	}
	if p.PageLimit != 20 || p.PageOffset != 40 {
		t.Errorf("page = %d/%d", p.PageLimit, p.PageOffset)
	}
	if p.Proto.String != "IPv6-ICMP" {
		t.Errorf("proto = %q, want eve canonical IPv6-ICMP", p.Proto.String)
	}
	if !p.Severity.Valid || p.Severity.Int32 != 2 || p.TriageStatus.String != "new" {
		t.Errorf("filters not mapped: %+v", p)
	}

	d, _ := parseAlertQuery(url.Values{})
	if d.SortKey != "ts" || !d.SortDesc || d.PageLimit != 50 || d.PageOffset != 0 {
		t.Errorf("defaults = %+v", d)
	}
}
