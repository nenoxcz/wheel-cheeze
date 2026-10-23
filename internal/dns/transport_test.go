package dns

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

func TestParseServer(t *testing.T) {
	cases := []struct {
		in       string
		scheme   string
		addr     string
		hostname string
		url      string
	}{
		{"1.1.1.1", "udp", "1.1.1.1:53", "", ""},
		{"1.1.1.1:5353", "udp", "1.1.1.1:5353", "", ""},
		{"udp://8.8.8.8", "udp", "8.8.8.8:53", "", ""},
		{"tcp://8.8.8.8", "tcp", "8.8.8.8:53", "", ""},
		{"tls://1.1.1.1", "tls", "1.1.1.1:853", "1.1.1.1", ""},
		{"tls://1.1.1.1#cloudflare-dns.com", "tls", "1.1.1.1:853", "cloudflare-dns.com", ""},
		{"tls://dns.google:853", "tls", "dns.google:853", "dns.google", ""},
		{"quic://dns.adguard.com", "quic", "dns.adguard.com:853", "dns.adguard.com", ""},
		{"https://cloudflare-dns.com/dns-query", "https", "cloudflare-dns.com:443", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"},
		{"https://9.9.9.9", "https", "9.9.9.9:443", "9.9.9.9", "https://9.9.9.9/dns-query"},
	}
	for _, tc := range cases {
		spec, err := parseServer(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if spec.scheme != tc.scheme || spec.addr != tc.addr || spec.hostname != tc.hostname || spec.url != tc.url {
			t.Errorf("%s: got %+v", tc.in, spec)
		}
	}
	for _, bad := range []string{"", "http://insecure", "gopher://x", "   "} {
		if _, err := parseServer(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// Encrypted DNS test servers, built on this repository's own TLS and QUIC.

var (
	encCertOnce sync.Once
	encCert     tls13.Certificate
	encPool     *x509.CertPool
)

func encServerCert(t testing.TB) (tls13.Certificate, *x509.CertPool) {
	encCertOnce.Do(func() {
		c, err := tls13.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
		if err != nil {
			panic(err)
		}
		encCert = c
		encPool = x509.NewCertPool()
		encPool.AddCert(c.Leaf)
	})
	return encCert, encPool
}

// answer runs the shared fake handler for a query and returns the response
// wire bytes.
func answer(h func(string) (byte, bool, bool), q []byte) []byte {
	fs := &fakeServer{handler: func(name string, _ Type, _ string) reply {
		rcode, hasAnswer, drop := h(name)
		if drop {
			return reply{drop: true}
		}
		r := reply{rcode: RCode(rcode)}
		if hasAnswer {
			r.answers = []RR{{Name: name, Type: TypeA, TTL: 60, Addr: addr("127.0.0.1")}}
		}
		return r
	}}
	return fs.respond(q, "tcp")
}

func startDoT(t *testing.T, h func(string) (byte, bool, bool)) string {
	t.Helper()
	cert, _ := encServerCert(t)
	ln, err := tls13.Listen("tcp", "127.0.0.1:0", &tls13.Config{Certificates: []tls13.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					q, err := readPrefixed(conn)
					if err != nil {
						return
					}
					if resp := answer(h, q); resp != nil {
						writePrefixed(conn, resp)
					}
				}
			}()
		}
	}()
	return "tls://" + ln.Addr().String()
}

func startDoQ(t *testing.T, h func(string) (byte, bool, bool)) string {
	t.Helper()
	cert, _ := encServerCert(t)
	l, err := quic.Listen("127.0.0.1:0", &tls13.Config{
		Certificates: []tls13.Certificate{cert},
		NextProtos:   []string{"doq"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						defer s.Close()
						q, err := readPrefixed(s)
						if err != nil {
							return
						}
						if resp := answer(h, q); resp != nil {
							writePrefixed(s, resp)
						}
					}()
				}
			}()
		}
	}()
	return "quic://" + l.Addr().String()
}

func startDoH(t *testing.T, h func(string) (byte, bool, bool)) string {
	t.Helper()
	cert, _ := encServerCert(t)
	ln, err := tls13.Listen("tcp", "127.0.0.1:0", &tls13.Config{
		Certificates: []tls13.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q, _ := io.ReadAll(io.LimitReader(r.Body, 65535))
		resp := answer(h, q)
		if resp == nil {
			http.Error(w, "dropped", http.StatusGatewayTimeout)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	return "https://" + net.JoinHostPort(host, port) + "/dns-query"
}

func encClient(server string, pool *x509.CertPool) *Client {
	return &Client{Config: &Config{
		Servers:  []string{server},
		Ndots:    1,
		Timeout:  4 * time.Second,
		Attempts: 1,
		TLSRoots: pool,
	}}
}

func TestEncryptedTransports(t *testing.T) {
	good := func(name string) (byte, bool, bool) { return 0, true, false }
	_, pool := encServerCert(t)
	servers := map[string]func(*testing.T, func(string) (byte, bool, bool)) string{
		"DoT": startDoT,
		"DoH": startDoH,
		"DoQ": startDoQ,
	}
	for name, start := range servers {
		t.Run(name, func(t *testing.T) {
			server := start(t, good)
			res, err := encClient(server, pool).LookupHost(context.Background(), "app.test")
			if err != nil {
				t.Fatalf("lookup over %s: %v", name, err)
			}
			if len(res.Addrs) != 1 || res.Addrs[0] != addr("127.0.0.1") {
				t.Fatalf("addrs %v", res.Addrs)
			}
			if res.Source != server {
				t.Fatalf("source %q", res.Source)
			}
			if len(res.Exchanges) == 0 || res.Exchanges[0].Err != nil {
				t.Fatalf("exchanges %+v", res.Exchanges)
			}
		})
	}
}

func TestEncryptedTransportsReportRCodes(t *testing.T) {
	// The encrypted transports still surface NXDOMAIN and the like.
	server := startDoT(t, func(name string) (byte, bool, bool) {
		return 3, false, false // NXDOMAIN
	})
	_, pool := encServerCert(t)
	_, err := encClient(server, pool).LookupHost(context.Background(), "nope.test")
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrNXDomain {
		t.Fatalf("got %v", err)
	}
}

func TestEncryptedTransportCertUntrusted(t *testing.T) {
	// Without the server's CA in the trust pool, the TLS handshake fails
	// and the lookup reports a network error rather than a DNS answer.
	server := startDoT(t, func(string) (byte, bool, bool) { return 0, true, false })
	_, err := encClient(server, x509.NewCertPool()).LookupHost(context.Background(), "app.test")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v (%T)", err, err)
	}
	if e.Kind != ErrNetwork && e.Kind != ErrTimeout {
		t.Fatalf("kind = %v", e.Kind)
	}
}

func TestDoHRejectsNonDNSContentType(t *testing.T) {
	cert, pool := encServerCert(t)
	ln, err := tls13.Listen("tcp", "127.0.0.1:0", &tls13.Config{
		Certificates: []tls13.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>captive portal</html>")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	server := "https://" + net.JoinHostPort(host, port) + "/dns-query"
	_, err = encClient(server, pool).LookupHost(context.Background(), "app.test")
	if err == nil {
		t.Fatal("a non-dns-message response was accepted")
	}
}
