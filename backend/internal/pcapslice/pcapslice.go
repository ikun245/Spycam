// Package pcapslice 从经典 libpcap 文件中按五元组（双向）与时间窗切出告警相关报文（S4 取证）。
// 只依赖标准库；pcapng 不支持，调用方据 ErrUnsupported 降级。
package pcapslice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// ErrUnsupported 表示输入不是可解析的经典 pcap（如 pcapng 或未知链路类型）。
var ErrUnsupported = errors.New("unsupported capture format")

// maxSnap 单包长度上限，防止畸形长度字段导致超大分配。
const maxSnap = 256 << 10

// Filter 描述切片条件。端口为 0 表示不按端口过滤（ICMP 等无端口协议）。
type Filter struct {
	A, B         netip.Addr
	PortA, PortB uint16
	Proto        uint8 // 6 TCP / 17 UDP / 1 ICMP；0 表示不限
	From, To     time.Time
}

// Result 汇总切片结果。Truncated 表示输入末尾有不完整记录（抓包被中断的常见情形），已丢弃该记录。
type Result struct {
	Total     int
	Matched   int
	Truncated bool
}

const (
	linkNull     = 0
	linkEthernet = 1
	linkRawAlt   = 12
	linkRaw      = 101
	linkLoop     = 108
	linkSLL      = 113
	linkIPv4     = 228
	linkIPv6     = 229
)

// Slice 读取 r 中的经典 pcap，把命中 f 的报文连同原全局头写入 w。
func Slice(r io.Reader, w io.Writer, f Filter) (Result, error) {
	var res Result
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return res, fmt.Errorf("read global header: %w", err)
	}
	var bo binary.ByteOrder
	nano := false
	switch {
	case binary.LittleEndian.Uint32(hdr) == 0xa1b2c3d4:
		bo = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr) == 0xa1b2c3d4:
		bo = binary.BigEndian
	case binary.LittleEndian.Uint32(hdr) == 0xa1b23c4d:
		bo, nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(hdr) == 0xa1b23c4d:
		bo, nano = binary.BigEndian, true
	default:
		return res, ErrUnsupported
	}
	link := bo.Uint32(hdr[20:]) & 0x0fffffff
	switch link {
	case linkNull, linkEthernet, linkRawAlt, linkRaw, linkLoop, linkSLL, linkIPv4, linkIPv6:
	default:
		return res, ErrUnsupported
	}
	if _, err := w.Write(hdr); err != nil {
		return res, err
	}

	rec := make([]byte, 16)
	for {
		if _, err := io.ReadFull(r, rec); err != nil {
			if errors.Is(err, io.EOF) {
				return res, nil
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				res.Truncated = true
				return res, nil
			}
			return res, fmt.Errorf("read record header: %w", err)
		}
		sec, frac := bo.Uint32(rec[0:]), bo.Uint32(rec[4:])
		inclLen := bo.Uint32(rec[8:])
		if inclLen > maxSnap {
			return res, fmt.Errorf("record length %d exceeds limit", inclLen)
		}
		data := make([]byte, inclLen)
		if _, err := io.ReadFull(r, data); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				res.Truncated = true
				return res, nil
			}
			return res, fmt.Errorf("read record body: %w", err)
		}
		res.Total++
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		ts := time.Unix(int64(sec), ns)
		if ts.Before(f.From) || ts.After(f.To) {
			continue
		}
		pkt, ok := parse(link, data)
		if !ok || !f.match(pkt) {
			continue
		}
		if _, err := w.Write(rec); err != nil {
			return res, err
		}
		if _, err := w.Write(data); err != nil {
			return res, err
		}
		res.Matched++
	}
}

type packet struct {
	src, dst         netip.Addr
	proto            uint8
	srcPort, dstPort uint16
}

func (f Filter) match(p packet) bool {
	if f.Proto != 0 && p.proto != f.Proto {
		return false
	}
	fwd := p.src == f.A && p.dst == f.B && portOK(f.PortA, p.srcPort) && portOK(f.PortB, p.dstPort)
	rev := p.src == f.B && p.dst == f.A && portOK(f.PortB, p.srcPort) && portOK(f.PortA, p.dstPort)
	return fwd || rev
}

func portOK(want, got uint16) bool { return want == 0 || want == got }

// parse 剥离链路层并解析 IPv4/IPv6 头与 TCP/UDP 端口；不处理 IPv6 扩展头，IPv4 非首片不带端口。
func parse(link uint32, b []byte) (packet, bool) {
	switch link {
	case linkEthernet:
		if len(b) < 14 {
			return packet{}, false
		}
		et, off := binary.BigEndian.Uint16(b[12:]), 14
		for (et == 0x8100 || et == 0x88a8) && len(b) >= off+4 { // VLAN
			et, off = binary.BigEndian.Uint16(b[off+2:]), off+4
		}
		if et != 0x0800 && et != 0x86dd {
			return packet{}, false
		}
		b = b[off:]
	case linkSLL:
		if len(b) < 16 {
			return packet{}, false
		}
		b = b[16:]
	case linkNull, linkLoop:
		if len(b) < 4 {
			return packet{}, false
		}
		b = b[4:]
	}
	if len(b) < 1 {
		return packet{}, false
	}
	var p packet
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return packet{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return packet{}, false
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		if binary.BigEndian.Uint16(b[6:])&0x1fff == 0 {
			l4 = b[ihl:]
		}
	case 6:
		if len(b) < 40 {
			return packet{}, false
		}
		p.proto = b[6]
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		l4 = b[40:]
	default:
		return packet{}, false
	}
	if (p.proto == 6 || p.proto == 17) && len(l4) >= 4 {
		p.srcPort = binary.BigEndian.Uint16(l4[0:])
		p.dstPort = binary.BigEndian.Uint16(l4[2:])
	}
	return p, true
}
