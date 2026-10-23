package netdiag

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// Test PKI.

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

var (
	caOnce sync.Once
	testCA *ca
)

func getCA() *ca {
	caOnce.Do(func() {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "netdiag test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		testCA = &ca{cert, key, pool}
	})
	return testCA
}

func leaf(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	c := getCA()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
}

func validLeaf(t *testing.T) tls.Certificate {
	return leaf(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "app.test")
}

// Fake DNS server: app.test and others resolve to 127.0.0.1.

// buildDNSResponse answers a raw DNS query per behavior, returning nil when
// the query should be dropped.
func buildDNSResponse(q []byte, behavior func(name string) (rcode byte, answer bool, drop bool)) []byte {
	// Parse the question name (no compression in queries).
	off := 12
	var labels []string
	for off < len(q) && q[off] != 0 {
		l := int(q[off])
		labels = append(labels, string(q[off+1:off+1+l]))
		off += 1 + l
	}
	qend := off + 5
	qtype := binary.BigEndian.Uint16(q[off+1:])
	rcode, answer, drop := behavior(strings.Join(labels, "."))
	if drop {
		return nil
	}
	resp := append([]byte(nil), q[:qend]...)
	binary.BigEndian.PutUint16(resp[2:], 0x8180|uint16(rcode))
	binary.BigEndian.PutUint16(resp[6:], 0)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	if answer && qtype == 1 && rcode == 0 {
		binary.BigEndian.PutUint16(resp[6:], 1)
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
	}
	return resp
}

func startDNS(t *testing.T, behavior func(name string) (rcode byte, answer bool, drop bool)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := buildDNSResponse(buf[:n], behavior); resp != nil {
				pc.WriteTo(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// startDoTServer runs a DNS-over-TLS server on this repository's TLS 1.3,
// answering with buildDNSResponse. It returns a tls:// server spec.
func startDoTServer(t *testing.T, behavior func(name string) (rcode byte, answer bool, drop bool)) string {
	t.Helper()
	c := validLeaf(t)
	ln, err := tls13.Listen("tcp", "127.0.0.1:0", &tls13.Config{
		Certificates: []tls13.Certificate{{Certificate: c.Certificate, PrivateKey: c.PrivateKey.(crypto.Signer)}},
	})
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
					var lb [2]byte
					if _, err := io.ReadFull(conn, lb[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(lb[:]))
					if _, err := io.ReadFull(conn, q); err != nil {
						return
					}
					resp := buildDNSResponse(q, behavior)
					if resp == nil {
						return
					}
					out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
					conn.Write(append(out, resp...))
				}
			}()
		}
	}()
	return "tls://" + ln.Addr().String() // hostname 127.0.0.1 matches the leaf IP SAN
}

func goodDNS(t *testing.T) string {
	return startDNS(t, func(name string) (byte, bool, bool) {
		switch name {
		case "nx.test":
			return 3, false, false
		case "fail.test":
			return 2, false, false
		case "empty.test":
			return 0, false, false
		}
		return 0, true, false
	})
}

// HTTPS server with a few paths.

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "netdiag-test")
		io.WriteString(w, "hello")
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) })
	return mux
}

func startHTTPS(t *testing.T, cert tls.Certificate, maxVersion uint16) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersion})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler(), ErrorLog: nil}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return portOf(ln.Addr().String())
}

func startHTTP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return portOf(ln.Addr().String())
}

// startRaw serves each TCP connection with fn.
func startRaw(t *testing.T, fn func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(c)
		}
	}()
	return portOf(ln.Addr().String())
}

func run(t *testing.T, target string, opts Options) *Report {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.HostsFile == "" {
		opts.HostsFile = "-"
	}
	r, err := Run(context.Background(), target, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func expect(t *testing.T, r *Report, stage Stage, status Status, code string) *Result {
	t.Helper()
	res := r.Stage(stage)
	if res == nil {
		t.Fatalf("no %s stage in report", stage)
	}
	if res.Status != status || (code != "" && res.Code != code) {
		var buf bytes.Buffer
		r.WriteText(&buf, false)
		t.Fatalf("%s: got status %s code %q, want %s %q\n%s", stage, res.Status, res.Code, status, code, buf.String())
	}
	return res
}

func TestAllStagesOK(t *testing.T) {
	dnsAddr := goodDNS(t)
	port := startHTTPS(t, validLeaf(t), 0)
	for _, impl := range []string{"stdlib", "wheel"} {
		t.Run(impl, func(t *testing.T) {
			r := run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: getCA().pool, TLSImpl: impl})
			if !r.OK || r.FailedStage != "" {
				t.Fatalf("report not OK: %+v", r)
			}
			expect(t, r, StageDNS, StatusOK, "")
			expect(t, r, StageTCP, StatusOK, "")
			tlsRes := expect(t, r, StageTLS, StatusOK, "")
			if !strings.Contains(tlsRes.Summary, "TLS 1.3") {
				t.Fatalf("TLS summary %q", tlsRes.Summary)
			}
			httpRes := expect(t, r, StageHTTP, StatusOK, "")
			if !strings.Contains(httpRes.Summary, "200 OK") {
				t.Fatalf("HTTP summary %q", httpRes.Summary)
			}
		})
	}
}

func TestDNSFailures(t *testing.T) {
	dnsAddr := goodDNS(t)
	for _, tc := range []struct{ host, code string }{
		{"nx.test", "dns.nxdomain"},
		{"fail.test", "dns.servfail"},
		{"empty.test", "dns.nodata"},
	} {
		r := run(t, "https://"+tc.host+"/", Options{DNSServer: dnsAddr})
		expect(t, r, StageDNS, StatusFail, tc.code)
		expect(t, r, StageTCP, StatusSkipped, "")
		if r.FailedStage != StageDNS || r.OK {
			t.Fatalf("verdict %v %v", r.FailedStage, r.OK)
		}
	}
	silent := startDNS(t, func(string) (byte, bool, bool) { return 0, false, true })
	r := run(t, "https://app.test/", Options{DNSServer: silent, Timeout: 600 * time.Millisecond})
	expect(t, r, StageDNS, StatusFail, "dns.timeout")
}

func TestTCPRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := portOf(ln.Addr().String())
	ln.Close()
	r := run(t, "https://127.0.0.1:"+port+"/", Options{})
	expect(t, r, StageDNS, StatusSkipped, "")
	res := expect(t, r, StageTCP, StatusFail, "tcp.refused")
	if !strings.Contains(res.Hint, "port "+port) {
		t.Fatalf("hint %q", res.Hint)
	}
}

func TestTLSCertificateProblems(t *testing.T) {
	dnsAddr := goodDNS(t)
	now := time.Now()
	selfSigned, _ := tls13.GenerateSelfSigned([]string{"app.test"}, time.Hour)
	cases := []struct {
		name string
		cert tls.Certificate
		code string
		want string
	}{
		{"hostname", leaf(t, now.Add(-time.Hour), now.Add(time.Hour), "other.test"), "tls.cert_hostname", "not valid for app.test"},
		{"expired", leaf(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour), "app.test"), "tls.cert_expired", "expired on"},
		{"not yet valid", leaf(t, now.Add(24*time.Hour), now.Add(48*time.Hour), "app.test"), "tls.cert_not_yet_valid", "not valid before"},
		{"self-signed", tls.Certificate{Certificate: selfSigned.Certificate, PrivateKey: selfSigned.PrivateKey}, "tls.cert_untrusted", "self-signed"},
	}
	for _, tc := range cases {
		for _, impl := range []string{"stdlib", "wheel"} {
			t.Run(tc.name+"/"+impl, func(t *testing.T) {
				port := startHTTPS(t, tc.cert, 0)
				r := run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: getCA().pool, TLSImpl: impl})
				res := expect(t, r, StageTLS, StatusFail, tc.code)
				if !strings.Contains(res.Summary, tc.want) {
					t.Fatalf("summary %q lacks %q", res.Summary, tc.want)
				}
				if len(res.Details) == 0 || !strings.HasPrefix(res.Details[0], "certificate: ") {
					t.Fatalf("certificate details missing: %v", res.Details)
				}
				expect(t, r, StageHTTP, StatusSkipped, "")

				// -insecure turns the failure into a pass.
				r = run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: getCA().pool, TLSImpl: impl, InsecureSkipVerify: true})
				expect(t, r, StageHTTP, StatusOK, "")
			})
		}
	}
}

func TestUntrustedCA(t *testing.T) {
	dnsAddr := goodDNS(t)
	port := startHTTPS(t, validLeaf(t), 0)
	r := run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: x509.NewCertPool()})
	res := expect(t, r, StageTLS, StatusFail, "tls.cert_untrusted")
	if !strings.Contains(res.Summary, "netdiag test CA") {
		t.Fatalf("summary %q", res.Summary)
	}
}

func TestCertificateExpiringSoon(t *testing.T) {
	dnsAddr := goodDNS(t)
	port := startHTTPS(t, leaf(t, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour), "app.test"), 0)
	r := run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: getCA().pool})
	expect(t, r, StageTLS, StatusWarn, "tls.cert_expiring")
	if !r.OK {
		t.Fatalf("a warning must not fail the report")
	}
}

func TestTLSProtocolProblems(t *testing.T) {
	t.Run("plaintext HTTP on an https URL", func(t *testing.T) {
		port := startHTTP(t)
		for _, impl := range []string{"stdlib", "wheel"} {
			r := run(t, "https://127.0.0.1:"+port+"/", Options{TLSImpl: impl})
			res := expect(t, r, StageTLS, StatusFail, "tls.not_tls")
			if !strings.Contains(res.Summary, "plaintext HTTP") {
				t.Fatalf("%s: summary %q", impl, res.Summary)
			}
		}
	})
	t.Run("server closes", func(t *testing.T) {
		port := startRaw(t, func(c net.Conn) {
			c.Read(make([]byte, 1024))
			c.Close()
		})
		for _, impl := range []string{"stdlib", "wheel"} {
			r := run(t, "https://127.0.0.1:"+port+"/", Options{TLSImpl: impl})
			expect(t, r, StageTLS, StatusFail, "tls.closed")
		}
	})
	t.Run("server silent", func(t *testing.T) {
		port := startRaw(t, func(c net.Conn) {
			time.Sleep(3 * time.Second)
			c.Close()
		})
		for _, impl := range []string{"stdlib", "wheel"} {
			r := run(t, "https://127.0.0.1:"+port+"/", Options{TLSImpl: impl, Timeout: 400 * time.Millisecond})
			expect(t, r, StageTLS, StatusFail, "tls.timeout")
		}
	})
	t.Run("TLS 1.2-only server with the TLS 1.3 client", func(t *testing.T) {
		dnsAddr := goodDNS(t)
		port := startHTTPS(t, validLeaf(t), tls.VersionTLS12)
		r := run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: getCA().pool, TLSImpl: "wheel"})
		res := expect(t, r, StageTLS, StatusFail, "tls.alert_protocol_version")
		if !strings.Contains(res.Hint, "-tls stdlib") {
			t.Fatalf("hint %q", res.Hint)
		}
		// crypto/tls negotiates TLS 1.2 fine.
		r = run(t, "https://app.test:"+port+"/", Options{DNSServer: dnsAddr, RootCAs: getCA().pool})
		if res := expect(t, r, StageTLS, StatusOK, ""); !strings.Contains(res.Summary, "TLS 1.2") {
			t.Fatalf("summary %q", res.Summary)
		}
	})
}

func TestHTTPStatuses(t *testing.T) {
	dnsAddr := goodDNS(t)
	port := startHTTPS(t, validLeaf(t), 0)
	opts := Options{DNSServer: dnsAddr, RootCAs: getCA().pool}

	r := run(t, "https://app.test:"+port+"/missing", opts)
	expect(t, r, StageHTTP, StatusWarn, "http.client_error")
	if !r.OK {
		t.Fatalf("404 must be a warning only")
	}
	r = run(t, "https://app.test:"+port+"/broken", opts)
	res := expect(t, r, StageHTTP, StatusFail, "http.server_error")
	if !strings.Contains(res.Hint, "unavailable") || r.FailedStage != StageHTTP {
		t.Fatalf("hint %q", res.Hint)
	}
	r = run(t, "https://app.test:"+port+"/redirect", opts)
	res = expect(t, r, StageHTTP, StatusOK, "")
	if !strings.Contains(strings.Join(res.Details, "\n"), "redirects to /elsewhere") {
		t.Fatalf("details %v", res.Details)
	}
}

func TestHTTPProtocolProblems(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		port := startRaw(t, func(c net.Conn) { time.Sleep(3 * time.Second); c.Close() })
		r := run(t, "http://127.0.0.1:"+port+"/", Options{Timeout: 400 * time.Millisecond})
		expect(t, r, StageHTTP, StatusFail, "http.timeout")
	})
	t.Run("not HTTP", func(t *testing.T) {
		port := startRaw(t, func(c net.Conn) {
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			time.Sleep(100 * time.Millisecond)
			c.Close()
		})
		r := run(t, "http://127.0.0.1:"+port+"/", Options{})
		res := expect(t, r, StageHTTP, StatusFail, "http.malformed")
		if !strings.Contains(strings.Join(res.Details, " "), "SSH-2.0") {
			t.Fatalf("details %v", res.Details)
		}
	})
	t.Run("closed", func(t *testing.T) {
		port := startRaw(t, func(c net.Conn) {
			c.Read(make([]byte, 4096))
			c.Close()
		})
		r := run(t, "http://127.0.0.1:"+port+"/", Options{})
		expect(t, r, StageHTTP, StatusFail, "http.closed")
	})
	t.Run("plain HTTP OK", func(t *testing.T) {
		port := startHTTP(t)
		r := run(t, "http://127.0.0.1:"+port+"/", Options{})
		if r.Stage(StageTLS) != nil {
			t.Fatalf("http:// must not have a TLS stage")
		}
		expect(t, r, StageHTTP, StatusOK, "")
	})
}

func TestQUICProbe(t *testing.T) {
	dnsAddr := goodDNS(t)
	port := startHTTPS(t, validLeaf(t), 0)
	opts := Options{DNSServer: dnsAddr, RootCAs: getCA().pool, QUIC: true, Timeout: 800 * time.Millisecond}

	// No UDP listener: the probe times out but the TCP path stays OK.
	r := run(t, "https://app.test:"+port+"/", opts)
	expect(t, r, StageQUIC, StatusFail, "quic.timeout")
	if !r.OK {
		t.Fatalf("a failed QUIC probe must not fail the TCP path")
	}

	// Our QUIC server on the same port number.
	cert := validLeaf(t)
	l, err := quic.Listen("127.0.0.1:"+port, &tls13.Config{
		Certificates: []tls13.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey.(*ecdsa.PrivateKey)}},
		NextProtos:   []string{"h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			if _, err := l.Accept(context.Background()); err != nil {
				return
			}
		}
	}()
	r = run(t, "https://app.test:"+port+"/", opts)
	res := expect(t, r, StageQUIC, StatusOK, "")
	if !strings.Contains(res.Summary, "ALPN h3") {
		t.Fatalf("summary %q", res.Summary)
	}
}

func TestEncryptedDNSResolver(t *testing.T) {
	// A full DNS -> TCP -> TLS -> HTTP run where the name is resolved over
	// DNS-over-TLS instead of cleartext UDP, as a censorship-circumvention
	// resolver would. app.example resolves to 127.0.0.1, where an HTTPS
	// server is listening.
	dot := startDoTServer(t, func(name string) (byte, bool, bool) {
		if name == "app.test" {
			return 0, true, false
		}
		return 3, false, false
	})
	port := startHTTPS(t, validLeaf(t), 0)
	r := run(t, "https://app.test:"+port+"/", Options{
		DNSServer: dot,
		RootCAs:   getCA().pool,
	})
	dnsRes := expect(t, r, StageDNS, StatusOK, "")
	if !strings.Contains(strings.Join(dnsRes.Details, "\n"), "DoT (DNS over TLS)") {
		t.Fatalf("DNS stage does not mention DoT: %v", dnsRes.Details)
	}
	if !strings.Contains(dnsRes.Summary, "127.0.0.1") {
		t.Fatalf("DNS summary %q", dnsRes.Summary)
	}
	expect(t, r, StageHTTP, StatusOK, "")
	if !r.OK {
		t.Fatalf("run not OK: failed at %s", r.FailedStage)
	}
}

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in, host, port, path string
		https                bool
	}{
		{"example.com", "example.com", "443", "/", true},
		{"example.com:80", "example.com", "80", "/", false},
		{"example.com:8443/x?y=1", "example.com", "8443", "/x?y=1", true},
		{"http://[::1]:8080/health", "::1", "8080", "/health", false},
		{"https://example.com", "example.com", "443", "/", true},
	} {
		got, err := parseTarget(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got.host != tc.host || got.port != tc.port || got.path != tc.path || got.https != tc.https {
			t.Fatalf("%s: got %+v", tc.in, got)
		}
	}
	for _, bad := range []string{"", "ftp://example.com", "https://"} {
		if _, err := parseTarget(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestReportRendering(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := portOf(ln.Addr().String())
	ln.Close()
	r := run(t, "https://127.0.0.1:"+port+"/", Options{})
	var text bytes.Buffer
	r.WriteText(&text, false)
	for _, want := range []string{"✘ TCP", "connection refused", "hint:", "- TLS", "FAILED at the TCP stage (tcp.refused)"} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text output lacks %q:\n%s", want, text.String())
		}
	}
	var js bytes.Buffer
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(js.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["failed_stage"] != "TCP" || decoded["ok"] != false {
		t.Fatalf("json %s", js.String())
	}
}
