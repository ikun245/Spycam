package httpapi

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"spycam/backend/internal/store/gen"
)

func TestParsePageParams(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantLimit  int32
		wantOffset int32
		wantErr    bool
	}{
		{name: "defaults", query: "", wantLimit: 50, wantOffset: 0},
		{name: "explicit", query: "limit=10&offset=20", wantLimit: 10, wantOffset: 20},
		{name: "max limit", query: "limit=200", wantLimit: 200},
		{name: "limit zero", query: "limit=0", wantErr: true},
		{name: "limit too large", query: "limit=201", wantErr: true},
		{name: "limit not number", query: "limit=abc", wantErr: true},
		{name: "negative offset", query: "offset=-1", wantErr: true},
		{name: "offset sql injection", query: "offset=1%3BDROP", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			limit, offset, err := parsePageParams(q)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if limit != tc.wantLimit || offset != tc.wantOffset {
				t.Fatalf("got (%d,%d), want (%d,%d)", limit, offset, tc.wantLimit, tc.wantOffset)
			}
		})
	}
}

func TestLastLine(t *testing.T) {
	cases := map[string]string{
		"":                                     "unknown error",
		"a\nb\n\n  ":                           "b",
		"Info: x\nError: bad rule at line 1\n": "Error: bad rule at line 1",
	}
	for in, want := range cases {
		if got := lastLine(in); got != want {
			t.Fatalf("lastLine(%q) = %q, want %q", in, got, want)
		}
	}
	if got := lastLine(strings.Repeat("x", 500)); len(got) != 300 {
		t.Fatalf("long line not truncated: %d", len(got))
	}
}

func TestToPcapViewHidesStoredPath(t *testing.T) {
	now := time.Now()
	v := toPcapView(gen.Pcap{
		ID:          "id-1",
		StoredPath:  "/data/pcaps/id-1.pcap",
		SizeBytes:   42,
		Sha256:      pgtype.Text{String: "abc", Valid: true},
		PacketCount: pgtype.Int8{},
		CreatedAt:   pgtype.Timestamptz{Time: now, Valid: true},
	})
	if v.Sha256 == nil || *v.Sha256 != "abc" {
		t.Fatalf("sha256 not mapped: %+v", v.Sha256)
	}
	if v.PacketCount != nil {
		t.Fatalf("null packet_count should stay nil")
	}
	if v.CreatedAt == nil || !v.CreatedAt.Equal(now) {
		t.Fatalf("created_at not mapped")
	}
}
