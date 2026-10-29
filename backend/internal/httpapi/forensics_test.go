package httpapi

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildForensicsFilter(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0)
	alert := func(src string, sport int32, proto string) alertTuple {
		return alertTuple{
			Ts:       pgtype.Timestamptz{Time: ts, Valid: true},
			SrcIp:    src,
			SrcPort:  pgtype.Int4{Int32: sport, Valid: sport != 0},
			DestIp:   "10.0.0.2",
			DestPort: pgtype.Int4{Int32: 80, Valid: sport != 0},
			Proto:    pgtype.Text{String: proto, Valid: true},
		}
	}
	cases := []struct {
		name      string
		a         alertTuple
		scope     string
		wantPorts [2]uint16
		wantProto uint8
		wantErr   bool
	}{
		{name: "flow default", a: alert("10.0.0.1", 1234, "TCP"), wantPorts: [2]uint16{1234, 80}, wantProto: 6},
		{name: "inet with prefix", a: alert("10.0.0.1/32", 1234, "TCP"), scope: "flow", wantPorts: [2]uint16{1234, 80}, wantProto: 6},
		{name: "hosts drops ports", a: alert("10.0.0.1", 1234, "TCP"), scope: "hosts", wantProto: 6},
		{name: "icmp no ports", a: alert("10.0.0.1", 0, "ICMP"), wantProto: 1},
		{name: "ipv6", a: alert("2001:db8::1", 53, "UDP"), wantPorts: [2]uint16{53, 80}, wantProto: 17},
		{name: "bad scope", a: alert("10.0.0.1", 1234, "TCP"), scope: "../etc", wantErr: true},
		{name: "bad ip", a: alert("not-an-ip", 1234, "TCP"), wantErr: true},
		{name: "no ts", a: alertTuple{SrcIp: "10.0.0.1", DestIp: "10.0.0.2"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := buildForensicsFilter(tc.a, tc.scope)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if f.PortA != tc.wantPorts[0] || f.PortB != tc.wantPorts[1] || f.Proto != tc.wantProto {
				t.Fatalf("got ports %d/%d proto %d", f.PortA, f.PortB, f.Proto)
			}
			if !f.From.Equal(ts.Add(-forensicsBefore)) || !f.To.Equal(ts.Add(forensicsAfter)) {
				t.Fatalf("bad window %v..%v", f.From, f.To)
			}
		})
	}
}
