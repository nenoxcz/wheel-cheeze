package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

const alpn = "wheel-interop"

var (
	certOnce sync.Once
	cert     tls13.Certificate
	pool     *x509.CertPool
)

func setup(t *testing.T) {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	certOnce.Do(func() {
		var err error
		cert, err = tls13.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
		if err != nil {
			panic(err)
		}
		pool = x509.NewCertPool()
		pool.AddCert(cert.Leaf)
	})
}

func logf(t *testing.T) func(string, ...any) {
	if !testing.Verbose() {
		return nil
	}
	return func(f string, a ...any) { t.Logf(f, a...) }
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// quic-go echo server.
func startQuicGoServer(t *testing.T, retry bool) net.Addr {
	setup(t)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quicgo.Transport{Conn: udp}
	if retry {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos:   []string{alpn},
	}
	ln, err := tr.Listen(tlsConf, &quicgo.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); tr.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
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
						io.Copy(s, s)
						s.Close()
					}()
				}
			}()
		}
	}()
	return udp.LocalAddr()
}

func dialOurs(t *testing.T, addr net.Addr, suites []uint16) *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := quic.Dial(ctx, addr.String(), &tls13.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		NextProtos:   []string{alpn},
		CipherSuites: suites,
	}, &quic.Config{Logf: logf(t)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func echoOurs(t *testing.T, c *quic.Conn, data []byte) {
	t.Helper()
	s, err := c.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(30 * time.Second))
	go func() {
		s.Write(data)
		s.Close()
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("echo mismatch: sent %d bytes, got %d", len(data), len(got))
	}
}

func TestOurClientQuicGoServer(t *testing.T) {
	for _, suite := range []uint16{tls13.TLS_AES_128_GCM_SHA256, tls13.TLS_AES_256_GCM_SHA384, tls13.TLS_CHACHA20_POLY1305_SHA256} {
		t.Run(tls13.CipherSuiteName(suite), func(t *testing.T) {
			addr := startQuicGoServer(t, false)
			c := dialOurs(t, addr, []uint16{suite})
			if got := c.ConnectionState().TLS.CipherSuite; got != suite {
				t.Fatalf("negotiated %s", tls13.CipherSuiteName(got))
			}
			echoOurs(t, c, []byte("hello quic-go"))
			// Large enough for quic-go to initiate its first key update
			// (after 100 packets) and for flow control updates.
			echoOurs(t, c, randomBytes(5<<20))
			// And a key update initiated by us.
			if err := c.UpdateKeys(); err != nil {
				t.Fatalf("UpdateKeys: %v", err)
			}
			echoOurs(t, c, randomBytes(300_000))
			t.Logf("stats: %+v", c.Stats())
		})
	}
}

func TestOurClientQuicGoServerRetry(t *testing.T) {
	addr := startQuicGoServer(t, true)
	c := dialOurs(t, addr, nil)
	if !c.ConnectionState().UsedRetry {
		t.Fatalf("quic-go did not send a Retry")
	}
	echoOurs(t, c, []byte("after retry"))
}

func TestOurClientManyStreamsQuicGoServer(t *testing.T) {
	addr := startQuicGoServer(t, false)
	c := dialOurs(t, addr, nil)
	var wg sync.WaitGroup
	for i := 0; i < 250; i++ { // above quic-go's default limit of 100
		wg.Add(1)
		go func() {
			defer wg.Done()
			echoOurs(t, c, []byte(fmt.Sprintf("stream %d", i)))
		}()
	}
	wg.Wait()
}

// Our echo server, quic-go client.
func startOurServer(t *testing.T, conf *quic.Config) *quic.Listener {
	setup(t)
	if conf == nil {
		conf = &quic.Config{}
	}
	conf.Logf = logf(t)
	l, err := quic.Listen("127.0.0.1:0", &tls13.Config{
		Certificates: []tls13.Certificate{cert},
		NextProtos:   []string{alpn},
	}, conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						io.Copy(s, s)
						s.Close()
					}()
				}
			}()
		}
	}()
	return l
}

func dialQuicGo(t *testing.T, addr string) quicgo.Connection {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := quicgo.DialAddr(ctx, addr, &tls.Config{ServerName: "localhost", RootCAs: pool, NextProtos: []string{alpn}}, &quicgo.Config{})
	if err != nil {
		t.Fatalf("quic-go dial: %v", err)
	}
	t.Cleanup(func() { c.CloseWithError(0, "") })
	return c
}

func echoQuicGo(t *testing.T, c quicgo.Connection, data []byte) {
	t.Helper()
	s, err := c.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(30 * time.Second))
	go func() {
		s.Write(data)
		s.Close()
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("echo mismatch: sent %d bytes, got %d", len(data), len(got))
	}
}

func TestQuicGoClientOurServer(t *testing.T) {
	l := startOurServer(t, nil)
	c := dialQuicGo(t, l.Addr().String())
	echoQuicGo(t, c, []byte("hello from quic-go"))
	echoQuicGo(t, c, randomBytes(5<<20))
	var wg sync.WaitGroup
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			echoQuicGo(t, c, randomBytes(10_000))
		}()
	}
	wg.Wait()
}

func TestQuicGoClientOurServerRetry(t *testing.T) {
	l := startOurServer(t, &quic.Config{RequireAddressValidation: true})
	c := dialQuicGo(t, l.Addr().String())
	echoQuicGo(t, c, []byte("validated"))
}

func TestQuicGoClientOurServerApplicationClose(t *testing.T) {
	setup(t)
	l, err := quic.Listen("127.0.0.1:0", &tls13.Config{Certificates: []tls13.Certificate{cert}, NextProtos: []string{alpn}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept(context.Background())
		if err == nil {
			c.CloseWithError(0x77, "bye from wheel-cheeze")
		}
	}()
	c := dialQuicGo(t, l.Addr().String())
	_, err = c.AcceptStream(context.Background())
	var appErr *quicgo.ApplicationError
	if !errors.As(err, &appErr) || appErr.ErrorCode != 0x77 || appErr.ErrorMessage != "bye from wheel-cheeze" {
		t.Fatalf("got %v", err)
	}
}
