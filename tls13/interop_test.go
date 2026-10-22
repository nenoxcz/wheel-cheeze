package tls13

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// echo copies everything it reads back to the writer until EOF.
func echo(rw io.ReadWriter) error {
	_, err := io.Copy(rw, rw)
	return err
}

// roundTrip writes msg and expects to read it back.
func roundTrip(t *testing.T, rw io.ReadWriter, msg []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := rw.Write(msg)
		errc <- err
	}()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(rw, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch")
	}
}

func stdServerConfig(t *testing.T, kind string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{toStdCert(leafCert(t, kind))},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"wheel/1", "h2"},
	}
}

func ourClientConfig(t *testing.T) *Config {
	return &Config{
		ServerName: "example.test",
		RootCAs:    getPKI(t).pool,
		NextProtos: []string{"h2", "wheel/1"},
	}
}

func TestClientAgainstStdlibServer(t *testing.T) {
	for _, suite := range []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256} {
		for _, kind := range []string{"p256", "p384", "p521", "rsa", "ed25519"} {
			t.Run(fmt.Sprintf("%s/%s", CipherSuiteName(suite), kind), func(t *testing.T) {
				a, b := pipe(t)
				srv := tls.Server(b, stdServerConfig(t, kind))
				go echo(srv)

				cfg := ourClientConfig(t)
				cfg.CipherSuites = []uint16{suite}
				c := Client(a, cfg)
				if err := c.Handshake(); err != nil {
					t.Fatalf("handshake: %v", err)
				}
				st := c.ConnectionState()
				if st.CipherSuite != suite || st.Version != versionTLS13 || !st.HandshakeComplete {
					t.Fatalf("unexpected state %+v", st)
				}
				if st.NegotiatedProtocol != "wheel/1" { // server preference
					t.Fatalf("ALPN = %q", st.NegotiatedProtocol)
				}
				if st.CurveID != X25519MLKEM768 {
					t.Fatalf("group = %v, want hybrid X25519MLKEM768", st.CurveID)
				}
				if len(st.VerifiedChains) == 0 {
					t.Fatalf("no verified chains")
				}
				roundTrip(t, c, []byte("hello over TLS 1.3"))
				big := make([]byte, 100_000)
				rand.Read(big)
				roundTrip(t, c, big)
				c.Close()
			})
		}
	}
}

func TestStdlibClientAgainstServer(t *testing.T) {
	for _, suite := range []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256} {
		for _, kind := range []string{"p256", "p384", "rsa", "ed25519"} {
			t.Run(fmt.Sprintf("%s/%s", CipherSuiteName(suite), kind), func(t *testing.T) {
				a, b := pipe(t)
				srv := Server(b, &Config{
					Certificates: []Certificate{leafCert(t, kind)},
					CipherSuites: []uint16{suite},
					NextProtos:   []string{"wheel/1"},
				})
				go echo(srv)

				c := tls.Client(a, &tls.Config{
					ServerName: "example.test",
					RootCAs:    getPKI(t).pool,
					NextProtos: []string{"h2", "wheel/1"},
				})
				if err := c.Handshake(); err != nil {
					t.Fatalf("handshake: %v", err)
				}
				st := c.ConnectionState()
				if st.CipherSuite != suite || st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "wheel/1" {
					t.Fatalf("unexpected state: suite %#x version %#x alpn %q", st.CipherSuite, st.Version, st.NegotiatedProtocol)
				}
				roundTrip(t, c, []byte("hello from crypto/tls"))
				big := make([]byte, 70_000)
				rand.Read(big)
				roundTrip(t, c, big)
				c.Close()
			})
		}
	}
}

func TestGroupsAndHelloRetryRequest(t *testing.T) {
	t.Run("our client, stdlib server forces HRR", func(t *testing.T) {
		for _, g := range []CurveID{CurveP256, CurveP384, CurveP521, X25519} {
			a, b := pipe(t)
			scfg := stdServerConfig(t, "p256")
			scfg.CurvePreferences = []tls.CurveID{tls.CurveID(g)}
			go echo(tls.Server(b, scfg))

			cfg := ourClientConfig(t)
			cfg.CurvePreferences = []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}
			if g == X25519 {
				cfg.CurvePreferences = []CurveID{CurveP256, X25519}
			}
			c := Client(a, cfg)
			if err := c.Handshake(); err != nil {
				t.Fatalf("%v: handshake: %v", g, err)
			}
			st := c.ConnectionState()
			if st.CurveID != g || !st.DidHelloRetryRequest {
				t.Fatalf("%v: got group %v, HRR %v", g, st.CurveID, st.DidHelloRetryRequest)
			}
			roundTrip(t, c, []byte("after HRR"))
		}
	})
	t.Run("stdlib client, our server forces HRR", func(t *testing.T) {
		for _, g := range []CurveID{CurveP256, CurveP384, CurveP521} {
			a, b := pipe(t)
			srv := Server(b, &Config{
				Certificates:     []Certificate{leafCert(t, "p256")},
				CurvePreferences: []CurveID{g},
			})
			go echo(srv)
			c := tls.Client(a, &tls.Config{ServerName: "example.test", RootCAs: getPKI(t).pool})
			if err := c.Handshake(); err != nil {
				t.Fatalf("%v: handshake: %v", g, err)
			}
			roundTrip(t, c, []byte("after HRR"))
			if st := srv.ConnectionState(); st.CurveID != g || !st.DidHelloRetryRequest {
				t.Fatalf("%v: server state %+v", g, st)
			}
		}
	})
	t.Run("classical X25519 without HRR", func(t *testing.T) {
		a, b := pipe(t)
		srv := Server(b, &Config{
			Certificates:     []Certificate{leafCert(t, "p256")},
			CurvePreferences: []CurveID{X25519},
		})
		go echo(srv)
		c := tls.Client(a, &tls.Config{ServerName: "example.test", RootCAs: getPKI(t).pool})
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		if st := srv.ConnectionState(); st.CurveID != X25519 || st.DidHelloRetryRequest {
			t.Fatalf("server state %+v", st)
		}
	})
}

func TestMutualAuth(t *testing.T) {
	clientCert := issue(t, "p256", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "client")

	t.Run("our client, stdlib server", func(t *testing.T) {
		a, b := pipe(t)
		scfg := stdServerConfig(t, "rsa")
		scfg.ClientAuth = tls.RequireAndVerifyClientCert
		scfg.ClientCAs = getPKI(t).pool
		srv := tls.Server(b, scfg)
		go echo(srv)
		cfg := ourClientConfig(t)
		cfg.Certificates = []Certificate{clientCert}
		c := Client(a, cfg)
		roundTrip(t, c, []byte("mutual"))
		if n := len(srv.ConnectionState().PeerCertificates); n != 2 {
			t.Fatalf("server saw %d client certificates", n)
		}
	})
	t.Run("stdlib client, our server", func(t *testing.T) {
		a, b := pipe(t)
		srv := Server(b, &Config{
			Certificates: []Certificate{leafCert(t, "ed25519")},
			ClientAuth:   RequireAndVerifyClientCert,
			ClientCAs:    getPKI(t).pool,
		})
		go echo(srv)
		c := tls.Client(a, &tls.Config{
			ServerName:   "example.test",
			RootCAs:      getPKI(t).pool,
			Certificates: []tls.Certificate{toStdCert(clientCert)},
		})
		roundTrip(t, c, []byte("mutual"))
		if st := srv.ConnectionState(); len(st.VerifiedChains) == 0 || st.SignatureScheme != ECDSAWithP256AndSHA256 {
			t.Fatalf("server state %+v", st)
		}
	})
	t.Run("missing client certificate", func(t *testing.T) {
		a, b := pipe(t)
		srv := Server(b, &Config{
			Certificates: []Certificate{leafCert(t, "p256")},
			ClientAuth:   RequireAndVerifyClientCert,
			ClientCAs:    getPKI(t).pool,
		})
		errc := make(chan error, 1)
		go func() { errc <- srv.Handshake() }()
		c := tls.Client(a, &tls.Config{ServerName: "example.test", RootCAs: getPKI(t).pool})
		c.Handshake()
		c.Read(make([]byte, 1)) // receive the alert
		err := <-errc
		var ae *AlertError
		if !errors.As(err, &ae) || ae.Alert != AlertCertificateRequired {
			t.Fatalf("server error = %v, want certificate_required", err)
		}
	})
}

func TestClientVerificationFailures(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		cert       Certificate
		serverName string
		roots      *x509.CertPool
		alert      Alert
		check      func(error) bool
	}{
		{
			name:       "hostname mismatch",
			cert:       leafCert(t, "p256"),
			serverName: "wrong.test",
			alert:      AlertBadCertificate,
			check:      func(err error) bool { var e x509.HostnameError; return errors.As(err, &e) },
		},
		{
			name:       "unknown authority",
			cert:       leafCert(t, "p256"),
			serverName: "example.test",
			roots:      x509.NewCertPool(),
			alert:      AlertUnknownCA,
			check:      func(err error) bool { var e x509.UnknownAuthorityError; return errors.As(err, &e) },
		},
		{
			name:       "expired",
			cert:       issue(t, "p256", now.Add(-48*time.Hour), now.Add(-24*time.Hour), "example.test"),
			serverName: "example.test",
			alert:      AlertCertificateExpired,
			check: func(err error) bool {
				var e x509.CertificateInvalidError
				return errors.As(err, &e) && e.Reason == x509.Expired
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := pipe(t)
			srvErr := make(chan error, 1)
			go func() {
				srv := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{toStdCert(tc.cert)}})
				srvErr <- srv.Handshake()
			}()
			roots := tc.roots
			if roots == nil {
				roots = getPKI(t).pool
			}
			err := Client(a, &Config{ServerName: tc.serverName, RootCAs: roots}).Handshake()
			var ae *AlertError
			if !errors.As(err, &ae) || ae.Remote || ae.Alert != tc.alert || !tc.check(err) {
				t.Fatalf("got %v (%T), want local %v", err, err, tc.alert)
			}
			// The stdlib server must have received our alert.
			if serr := <-srvErr; serr == nil || !strings.Contains(serr.Error(), "remote error") {
				t.Fatalf("server error = %v", serr)
			}
		})
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	t.Run("TLS 1.2-only server", func(t *testing.T) {
		// We only offer TLS 1.3, so the server finds no common version
		// and aborts with protocol_version itself.
		a, b := pipe(t)
		go tls.Server(b, &tls.Config{
			Certificates: []tls.Certificate{toStdCert(leafCert(t, "p256"))},
			MaxVersion:   tls.VersionTLS12,
		}).Handshake()
		err := Client(a, ourClientConfig(t)).Handshake()
		var ae *AlertError
		if !errors.As(err, &ae) || !ae.Remote || ae.Alert != AlertProtocolVersion {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("server answers with a TLS 1.2 ServerHello", func(t *testing.T) {
		a, b := pipe(t)
		go func() {
			buf := make([]byte, 4096)
			b.Read(buf)
			sh := marshalMessage(typeServerHello, func(bb *builder) {
				bb.u16(versionTLS12)
				bb.raw(make([]byte, 32))
				bb.bytes8(nil)
				bb.u16(0xc02f) // ECDHE-RSA-AES128-GCM-SHA256
				bb.u8(0)
			})
			b.Write(append([]byte{recordHandshake, 3, 3, 0, byte(len(sh))}, sh...))
		}()
		err := Client(a, ourClientConfig(t)).Handshake()
		var ae *AlertError
		if !errors.As(err, &ae) || ae.Remote || ae.Alert != AlertProtocolVersion ||
			!strings.Contains(err.Error(), "does not support TLS 1.3") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("TLS 1.2-only client", func(t *testing.T) {
		a, b := pipe(t)
		errc := make(chan error, 1)
		go func() {
			errc <- Server(b, &Config{Certificates: []Certificate{leafCert(t, "p256")}}).Handshake()
		}()
		err := tls.Client(a, &tls.Config{ServerName: "example.test", RootCAs: getPKI(t).pool, MaxVersion: tls.VersionTLS12}).Handshake()
		if err == nil || !strings.Contains(err.Error(), "protocol version") {
			t.Fatalf("client error = %v", err)
		}
		var ae *AlertError
		if serr := <-errc; !errors.As(serr, &ae) || ae.Alert != AlertProtocolVersion {
			t.Fatalf("server error = %v", serr)
		}
	})
}

func TestALPNMismatch(t *testing.T) {
	a, b := pipe(t)
	scfg := stdServerConfig(t, "p256")
	scfg.NextProtos = []string{"only-this"}
	go tls.Server(b, scfg).Handshake()
	cfg := ourClientConfig(t)
	cfg.NextProtos = []string{"something-else"}
	err := Client(a, cfg).Handshake()
	var ae *AlertError
	if !errors.As(err, &ae) || !ae.Remote || ae.Alert != AlertNoApplicationProtocol {
		t.Fatalf("got %v", err)
	}
}

func TestNotTLS(t *testing.T) {
	a, b := pipe(t)
	go func() {
		buf := make([]byte, 1024)
		b.Read(buf)
		b.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()
	err := Client(a, ourClientConfig(t)).Handshake()
	var rh *RecordHeaderError
	if !errors.As(err, &rh) || string(rh.Header[:]) != "HTTP/" {
		t.Fatalf("got %v", err)
	}
}

func TestExportKeyingMaterialMatchesStdlib(t *testing.T) {
	a, b := pipe(t)
	srv := tls.Server(b, stdServerConfig(t, "p256"))
	done := make(chan []byte, 1)
	go func() {
		if err := srv.Handshake(); err != nil {
			done <- nil
			return
		}
		st := srv.ConnectionState()
		ekm, _ := st.ExportKeyingMaterial("EXPERIMENTAL wheel", []byte("ctx"), 42)
		done <- ekm
	}()
	c := Client(a, ourClientConfig(t))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	ours, err := c.ExportKeyingMaterial("EXPERIMENTAL wheel", []byte("ctx"), 42)
	if err != nil {
		t.Fatal(err)
	}
	if theirs := <-done; !bytes.Equal(ours, theirs) {
		t.Fatalf("exporter mismatch:\n ours   %x\n theirs %x", ours, theirs)
	}
}

func TestKeyUpdateAndLargeTransfer(t *testing.T) {
	// Against crypto/tls, so both directions of KeyUpdate are exercised
	// with an independent implementation.
	a, b := pipe(t)
	srv := tls.Server(b, stdServerConfig(t, "p256"))
	go echo(srv)
	c := Client(a, ourClientConfig(t))
	payload := make([]byte, 1<<20)
	rand.Read(payload)
	roundTrip(t, c, payload[:1000])
	for i := 0; i < 3; i++ {
		if err := c.UpdateKeys(true); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, payload)
	}
	if c.in.epoch < 4 || c.out.epoch < 5 {
		t.Fatalf("keys were not updated: read epoch %d, write epoch %d", c.in.epoch, c.out.epoch)
	}
}

func TestSelfToSelf(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(reloaded.Leaf)

	l, err := Listen("tcp", "127.0.0.1:0", &Config{Certificates: []Certificate{reloaded}, NextProtos: []string{"echo"}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				echo(c)
			}()
		}
	}()

	var keylog bytes.Buffer
	c, err := Dial("tcp", l.Addr().String(), &Config{RootCAs: pool, NextProtos: []string{"echo"}, KeyLogWriter: &keylog})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c, []byte("self to self"))
	if err := c.UpdateKeys(true); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, bytes.Repeat([]byte("x"), 50_000))

	// close_notify after CloseWrite must surface as io.EOF on the server
	// side, which then closes; we then read EOF.
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after CloseWrite = %v, want EOF", err)
	}

	lines := strings.Split(strings.TrimSpace(keylog.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("key log has %d lines:\n%s", len(lines), keylog.String())
	}
	for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"} {
		if !strings.Contains(keylog.String(), label+" ") {
			t.Fatalf("key log lacks %s", label)
		}
	}
}
