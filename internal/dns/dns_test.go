package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// reply describes how the fake server answers one query.
type reply struct {
	rcode     RCode
	answers   []RR
	truncate  bool // set TC and drop answers over UDP
	drop      bool // send nothing
	garbage   bool // send bytes that do not parse
	wrongID   bool // first send a response with a mismatched ID
	noRA      bool
	authority []RR
}

type fakeServer struct {
	addr    string
	queries atomic.Int32
	handler func(name string, qtype Type, proto string) reply
}

func appendRR(b []byte, rr RR) []byte {
	b, _ = appendName(b, rr.Name)
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Type))
	b = binary.BigEndian.AppendUint16(b, classIN)
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	var rdata []byte
	switch rr.Type {
	case TypeA, TypeAAAA:
		rdata = rr.Addr.AsSlice()
	case TypeCNAME, TypeNS:
		rdata, _ = appendName(nil, rr.Data)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func (s *fakeServer) respond(q []byte, proto string) []byte {
	s.queries.Add(1)
	m, err := parseMessage(q)
	if err != nil {
		return nil
	}
	r := s.handler(m.QName, m.QType, proto)
	if r.drop {
		return nil
	}
	if r.garbage {
		return []byte{q[0], q[1], 0x81}
	}
	flags := uint16(flagQR | flagRD | uint16(r.rcode))
	if !r.noRA {
		flags |= flagRA
	}
	answers := r.answers
	if r.truncate && proto == "udp" {
		flags |= flagTC
		answers = nil
	}
	b := make([]byte, 12)
	copy(b, q[:2])
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(b[8:], uint16(len(r.authority)))
	b, _ = appendName(b, m.QName)
	b = binary.BigEndian.AppendUint16(b, uint16(m.QType))
	b = binary.BigEndian.AppendUint16(b, classIN)
	for _, rr := range answers {
		b = appendRR(b, rr)
	}
	for _, rr := range r.authority {
		b = appendRR(b, rr)
	}
	return b
}

func startFakeServer(t *testing.T, handler func(name string, qtype Type, proto string) reply) *fakeServer {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; i < 20; i++ {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
	}
	if ln == nil {
		t.Fatal("could not bind UDP and TCP on the same port")
	}
	s := &fakeServer{addr: pc.LocalAddr().String(), handler: handler}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			m, _ := parseMessage(q)
			if m != nil {
				if r := handler(m.QName, m.QType, "udp"); r.wrongID {
					bad := s.respond(q, "udp")
					bad[0] ^= 0xff
					pc.WriteTo(bad, addr)
					s.queries.Add(-1)
				}
			}
			if resp := s.respond(q, "udp"); resp != nil {
				pc.WriteTo(resp, addr)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				if resp := s.respond(q, "tcp"); resp != nil {
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
				}
			}()
		}
	}()
	return s
}

func client(servers ...string) *Client {
	return &Client{Config: &Config{Servers: servers, Ndots: 1, Timeout: 300 * time.Millisecond, Attempts: 2}}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestResolveWithCNAME(t *testing.T) {
	s := startFakeServer(t, func(name string, qtype Type, _ string) reply {
		if name != "www.example.test" {
			return reply{rcode: RCodeNXDomain}
		}
		r := reply{answers: []RR{{Name: "www.example.test", Type: TypeCNAME, TTL: 60, Data: "edge.cdn.test"}}}
		if qtype == TypeA {
			r.answers = append(r.answers, RR{Name: "edge.cdn.test", Type: TypeA, TTL: 60, Addr: addr("192.0.2.10")})
		} else {
			r.answers = append(r.answers, RR{Name: "edge.cdn.test", Type: TypeAAAA, TTL: 60, Addr: addr("2001:db8::10")})
		}
		return r
	})
	res, err := client(s.addr).LookupHost(context.Background(), "www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Addrs) != 2 || res.Canonical != "edge.cdn.test" || len(res.CNAMEs) != 1 || res.Source != s.addr {
		t.Fatalf("result %+v", res)
	}
}

func TestNXDomain(t *testing.T) {
	s := startFakeServer(t, func(string, Type, string) reply { return reply{rcode: RCodeNXDomain} })
	_, err := client(s.addr).LookupHost(context.Background(), "nope.example.test")
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrNXDomain {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Fatalf("message %q", err)
	}
}

func TestNoData(t *testing.T) {
	s := startFakeServer(t, func(string, Type, string) reply { return reply{} })
	_, err := client(s.addr).LookupHost(context.Background(), "empty.example.test")
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrNoData {
		t.Fatalf("got %v", err)
	}
}

func TestServFailFallsBackToNextServer(t *testing.T) {
	bad := startFakeServer(t, func(string, Type, string) reply { return reply{rcode: RCodeServFail} })
	good := startFakeServer(t, func(_ string, qtype Type, _ string) reply {
		if qtype == TypeA {
			return reply{answers: []RR{{Name: "x.test", Type: TypeA, Addr: addr("192.0.2.1")}}}
		}
		return reply{}
	})
	res, err := client(bad.addr, good.addr).LookupHost(context.Background(), "x.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != good.addr || len(res.Addrs) != 1 {
		t.Fatalf("result %+v", res)
	}
}

func TestRefusedEverywhere(t *testing.T) {
	s := startFakeServer(t, func(string, Type, string) reply { return reply{rcode: RCodeRefused} })
	_, err := client(s.addr).LookupHost(context.Background(), "x.test")
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrRefused || e.Server != s.addr {
		t.Fatalf("got %v", err)
	}
}

func TestTimeout(t *testing.T) {
	s := startFakeServer(t, func(string, Type, string) reply { return reply{drop: true} })
	start := time.Now()
	_, err := client(s.addr).LookupHost(context.Background(), "x.test")
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrTimeout {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	s := startFakeServer(t, func(_ string, qtype Type, proto string) reply {
		if qtype != TypeA {
			return reply{}
		}
		var rrs []RR
		for i := 1; i <= 40; i++ {
			rrs = append(rrs, RR{Name: "big.test", Type: TypeA, Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
		}
		return reply{answers: rrs, truncate: true}
	})
	res, err := client(s.addr).LookupHost(context.Background(), "big.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Addrs) != 40 {
		t.Fatalf("got %d addresses", len(res.Addrs))
	}
	tcp := false
	for _, ex := range res.Exchanges {
		tcp = tcp || ex.Proto == "tcp"
	}
	if !tcp {
		t.Fatalf("no TCP exchange recorded")
	}
}

func TestMismatchedIDIsIgnored(t *testing.T) {
	s := startFakeServer(t, func(_ string, qtype Type, _ string) reply {
		if qtype == TypeA {
			return reply{wrongID: true, answers: []RR{{Name: "x.test", Type: TypeA, Addr: addr("192.0.2.7")}}}
		}
		return reply{}
	})
	res, err := client(s.addr).LookupHost(context.Background(), "x.test")
	if err != nil || len(res.Addrs) != 1 {
		t.Fatalf("got %v %+v", err, res)
	}
}

func TestMalformed(t *testing.T) {
	s := startFakeServer(t, func(string, Type, string) reply { return reply{garbage: true} })
	_, err := client(s.addr).LookupHost(context.Background(), "x.test")
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrMalformed {
		t.Fatalf("got %v", err)
	}
}

func TestSearchList(t *testing.T) {
	s := startFakeServer(t, func(name string, qtype Type, _ string) reply {
		if name == "db.corp.test" && qtype == TypeA {
			return reply{answers: []RR{{Name: name, Type: TypeA, Addr: addr("10.1.2.3")}}}
		}
		if name == "db.corp.test" {
			return reply{}
		}
		return reply{rcode: RCodeNXDomain}
	})
	c := client(s.addr)
	c.Config.Search = []string{"corp.test"}
	res, err := c.LookupHost(context.Background(), "db")
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "db.corp.test" {
		t.Fatalf("resolved %q", res.Name)
	}
}

func TestHostsFileAndResolvConf(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	os.WriteFile(hosts, []byte("127.0.0.1 localhost\n# comment\n10.9.8.7 printer.lan printer\n"), 0o644)
	c := client()
	c.Config.HostsFile = hosts
	res, err := c.LookupHost(context.Background(), "printer")
	if err != nil || res.Source != "hosts" || res.Addrs[0] != addr("10.9.8.7") {
		t.Fatalf("got %v %+v", err, res)
	}

	rc := filepath.Join(dir, "resolv.conf")
	os.WriteFile(rc, []byte("nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\nsearch a.test b.test\noptions ndots:2 timeout:3 attempts:4\n"), 0o644)
	cfg, err := ReadResolvConf(rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 2 || cfg.Servers[1] != "[2606:4700:4700::1111]:53" || cfg.Ndots != 2 ||
		cfg.Timeout != 3*time.Second || cfg.Attempts != 4 || len(cfg.Search) != 2 {
		t.Fatalf("config %+v", cfg)
	}
}

func TestNameCompressionLoop(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, 0xc0, 12) // pointer to itself
	if _, err := parseMessage(msg); err == nil {
		t.Fatal("compression loop accepted")
	}
}

func FuzzParseMessage(f *testing.F) {
	q, _ := buildQuery(1, "www.example.test", TypeA)
	f.Add(q)
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := parseMessage(b); err == nil {
			m.addresses(m.QName, TypeA)
		}
	})
}
