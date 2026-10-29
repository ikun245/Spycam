package aggregate

import (
	"testing"
	"time"
)

func TestGroupHashWindowBucketing(t *testing.T) {
	// 同五元组，60s 窗口：同桶合并、跨桶分组的键必须不同
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := base.Unix() / 60
	b2 := base.Add(59 * time.Second).Unix() / 60
	b3 := base.Add(61 * time.Second).Unix() / 60

	if b1 != b2 {
		t.Fatalf("59s apart must be same bucket")
	}
	if b1 == b3 {
		t.Fatalf("61s apart must be different bucket")
	}

	h1 := GroupHash(1000001, "10.0.0.66", 0, "10.0.0.5", 22, "TCP", b1)
	h2 := GroupHash(1000001, "10.0.0.66", 0, "10.0.0.5", 22, "TCP", b2)
	h3 := GroupHash(1000001, "10.0.0.66", 0, "10.0.0.5", 22, "TCP", b3)

	if h1 != h2 {
		t.Fatalf("same window must produce same group hash")
	}
	if h1 == h3 {
		t.Fatalf("adjacent windows must produce different group hash")
	}
}

func TestGroupHashDistinctTuple(t *testing.T) {
	h := GroupHash(1000001, "10.0.0.66", 0, "10.0.0.5", 22, "TCP", 1)
	hDst := GroupHash(1000001, "10.0.0.66", 0, "10.0.0.5", 23, "TCP", 1)
	hSid := GroupHash(1000002, "10.0.0.66", 0, "10.0.0.5", 22, "TCP", 1)

	if h == hDst {
		t.Fatalf("dest port participates in hash")
	}
	if h == hSid {
		t.Fatalf("sid participates in hash")
	}
}
