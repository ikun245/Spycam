package pcapslice

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

var base = time.Unix(1_700_000_000, 0)

func ipv4TCP(src, dst string, sport, dport uint16) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	b[9] = 6
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	return b
}

func ether(payload []byte) []byte {
	b := make([]byte, 14, 14+len(payload))
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	return append(b, payload...)
}

type rec struct {
	at   time.Time
	data []byte
}

func buildPcap(link uint32, recs []rec) []byte {
	var buf bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], link)
	buf.Write(h)
	for _, r := range recs {
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[0:], uint32(r.at.Unix()))
		binary.LittleEndian.PutUint32(rh[4:], uint32(r.at.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:], uint32(len(r.data)))
		binary.LittleEndian.PutUint32(rh[12:], uint32(len(r.data)))
		buf.Write(rh)
		buf.Write(r.data)
	}
	return buf.Bytes()
}

func TestSlice(t *testing.T) {
	flt := Filter{
		A: netip.MustParseAddr("10.0.0.1"), B: netip.MustParseAddr("10.0.0.2"),
		PortA: 1234, PortB: 80, Proto: 6,
		From: base.Add(-time.Minute), To: base.Add(time.Minute),
	}
	recs := []rec{
		{base, ipv4TCP("10.0.0.1", "10.0.0.2", 1234, 80)},                      // 正向命中
		{base.Add(time.Second), ipv4TCP("10.0.0.2", "10.0.0.1", 80, 1234)},     // 反向命中
		{base, ipv4TCP("10.0.0.1", "10.0.0.2", 9999, 80)},                      // 端口不符
		{base, ipv4TCP("10.0.0.3", "10.0.0.2", 1234, 80)},                      // IP 不符
		{base.Add(2 * time.Minute), ipv4TCP("10.0.0.1", "10.0.0.2", 1234, 80)}, // 时间窗外
	}
	cases := []struct {
		name string
		link uint32
		wrap func([]byte) []byte
	}{
		{name: "raw ip", link: linkRaw, wrap: func(b []byte) []byte { return b }},
		{name: "ethernet", link: linkEthernet, wrap: ether},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := make([]rec, len(recs))
			for i, r := range recs {
				wrapped[i] = rec{r.at, tc.wrap(r.data)}
			}
			var out bytes.Buffer
			res, err := Slice(bytes.NewReader(buildPcap(tc.link, wrapped)), &out, flt)
			if err != nil {
				t.Fatal(err)
			}
			if res.Total != 5 || res.Matched != 2 {
				t.Fatalf("got %+v, want total 5 matched 2", res)
			}
			// 输出本身应是合法 pcap，且再切一次结果不变
			res2, err := Slice(bytes.NewReader(out.Bytes()), &bytes.Buffer{}, flt)
			if err != nil || res2.Total != 2 || res2.Matched != 2 {
				t.Fatalf("re-slice got %+v err %v", res2, err)
			}
		})
	}
}

func TestSliceUnsupportedAndMalformed(t *testing.T) {
	pcapng := []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := Slice(bytes.NewReader(pcapng), &bytes.Buffer{}, Filter{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("pcapng: err = %v, want ErrUnsupported", err)
	}
	huge := buildPcap(linkRaw, nil)
	rh := make([]byte, 16)
	binary.LittleEndian.PutUint32(rh[8:], maxSnap+1)
	huge = append(huge, rh...)
	if _, err := Slice(bytes.NewReader(huge), &bytes.Buffer{}, Filter{}); err == nil {
		t.Fatal("oversized record should fail")
	}
	two := buildPcap(linkRaw, []rec{
		{base, ipv4TCP("10.0.0.1", "10.0.0.2", 1, 2)},
		{base, ipv4TCP("10.0.0.1", "10.0.0.2", 1, 2)},
	})
	res, err := Slice(bytes.NewReader(two[:len(two)-5]), &bytes.Buffer{}, Filter{
		A: netip.MustParseAddr("10.0.0.1"), B: netip.MustParseAddr("10.0.0.2"),
		From: base.Add(-time.Second), To: base.Add(time.Second),
	})
	if err != nil || !res.Truncated || res.Total != 1 || res.Matched != 1 {
		t.Fatalf("truncated tail: res %+v err %v, want 1 complete packet kept and Truncated", res, err)
	}
}

// 用仓库内真实的 Scapy 造数 pcap 验证链路类型与解析：一次 C2 心跳是 6 个报文的完整 TCP 会话。
func TestSliceRealScenarioPcap(t *testing.T) {
	f, err := os.Open("../../../validation/out/c2_beacon.pcap")
	if err != nil {
		t.Skip("scenario pcap not present:", err)
	}
	defer f.Close()
	res, err := Slice(f, &bytes.Buffer{}, Filter{
		A: netip.MustParseAddr("10.0.0.100"), B: netip.MustParseAddr("198.51.100.10"),
		PortA: 46000, PortB: 80, Proto: 6,
		From: time.Unix(0, 0), To: time.Unix(1<<40, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 360 || res.Matched != 6 {
		t.Fatalf("got %+v, want total 360 matched 6", res)
	}
}
