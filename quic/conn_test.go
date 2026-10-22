package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nenoxcz/wheel-cheeze/tls13"
)

var (
	certOnce sync.Once
	testCert tls13.Certificate
	testPool *x509.CertPool
)

func serverTLS(t testing.TB) *tls13.Config {
	certOnce.Do(func() {
		var err error
		testCert, err = tls13.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
		if err != nil {
			panic(err)
		}
		testPool = x509.NewCertPool()
		testPool.AddCert(testCert.Leaf)
	})
	return &tls13.Config{Certificates: []tls13.Certificate{testCert}, NextProtos: []string{"wheel-test"}}
}

func clientTLS(t testing.TB) *tls13.Config {
	serverTLS(t)
	return &tls13.Config{ServerName: "localhost", RootCAs: testPool, NextProtos: []string{"wheel-test"}}
}

func testLogf(t testing.TB) func(string, ...any) {
	if !testing.Verbose() {
		return nil
	}
	return func(format string, args ...any) { t.Logf(format, args...) }
}

// echoServer accepts connections and echoes every bidirectional stream.
func echoServer(t testing.TB, pc net.PacketConn, conf *Config) *Listener {
	t.Helper()
	if pc == nil {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	if conf == nil {
		conf = &Config{}
	}
	if conf.Logf == nil {
		conf.Logf = testLogf(t)
	}
	l, err := NewListener(pc, serverTLS(t), conf)
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

func dial(t testing.TB, addr string, conf *Config) *Conn {
	t.Helper()
	if conf == nil {
		conf = &Config{}
	}
	if conf.Logf == nil {
		conf.Logf = testLogf(t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr, clientTLS(t), conf)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// echoStream sends data on a new stream, closes it and returns what the
// echo server sent back.
func echoStream(t testing.TB, c *Conn, data []byte) []byte {
	t.Helper()
	s, err := c.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.SetDeadline(time.Now().Add(30 * time.Second))
	errc := make(chan error, 1)
	go func() {
		_, err := s.Write(data)
		if err == nil {
			err = s.Close()
		}
		errc <- err
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	return got
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestHandshakeAndEcho(t *testing.T) {
	l := echoServer(t, nil, nil)
	c := dial(t, l.Addr().String(), nil)
	st := c.ConnectionState()
	if !st.TLS.HandshakeComplete || st.TLS.NegotiatedProtocol != "wheel-test" || st.Version != version1 {
		t.Fatalf("state %+v", st)
	}
	if got := echoStream(t, c, []byte("hello quic")); string(got) != "hello quic" {
		t.Fatalf("echo = %q", got)
	}
	// An empty stream (FIN only).
	if got := echoStream(t, c, nil); len(got) != 0 {
		t.Fatalf("empty echo = %q", got)
	}
}

func TestLargeTransferAndConcurrentStreams(t *testing.T) {
	l := echoServer(t, nil, nil)
	c := dial(t, l.Addr().String(), nil)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := randomBytes(3 << 20)
			got := echoStream(t, c, data)
			if !bytes.Equal(got, data) {
				t.Errorf("stream echo mismatch: %d bytes back", len(got))
			}
		}()
	}
	wg.Wait()
	st := c.Stats()
	t.Logf("stats: %+v", st)
}

func TestStreamLimitCredit(t *testing.T) {
	l := echoServer(t, nil, &Config{MaxIncomingStreams: 10})
	c := dial(t, l.Addr().String(), nil)
	// 50 sequential streams against a limit of 10 only works if the server
	// returns credit with MAX_STREAMS as streams finish.
	for i := 0; i < 50; i++ {
		msg := []byte(fmt.Sprintf("stream %d", i))
		if got := echoStream(t, c, msg); !bytes.Equal(got, msg) {
			t.Fatalf("stream %d: got %q", i, got)
		}
	}
	if _, err := c.OpenStream(); err != nil && !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("OpenStream: %v", err)
	}
}

// lossyConn drops and reorders outgoing datagrams.
type lossyConn struct {
	net.PacketConn
	mu      sync.Mutex
	rnd     *mrand.Rand
	drop    float64
	reorder float64
	dropped int
}

func (l *lossyConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	l.mu.Lock()
	r := l.rnd.Float64()
	l.mu.Unlock()
	switch {
	case r < l.drop:
		l.mu.Lock()
		l.dropped++
		l.mu.Unlock()
		return len(b), nil
	case r < l.drop+l.reorder:
		cp := append([]byte(nil), b...)
		time.AfterFunc(15*time.Millisecond, func() { l.PacketConn.WriteTo(cp, addr) })
		return len(b), nil
	}
	return l.PacketConn.WriteTo(b, addr)
}

func (l *lossyConn) droppedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

func TestLossyNetwork(t *testing.T) {
	spc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lossyServer := &lossyConn{PacketConn: spc, rnd: mrand.New(mrand.NewSource(1)), drop: 0.1, reorder: 0.1}
	l := echoServer(t, lossyServer, nil)

	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lossyClient := &lossyConn{PacketConn: cpc, rnd: mrand.New(mrand.NewSource(2)), drop: 0.1, reorder: 0.1}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := DialConn(ctx, lossyClient, l.Addr(), clientTLS(t), &Config{Logf: testLogf(t)})
	if err != nil {
		t.Fatalf("dial over lossy link: %v", err)
	}
	defer c.Close()

	data := randomBytes(1 << 20)
	got := echoStream(t, c, data)
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatalf("data corrupted: got %d bytes", len(got))
	}
	st := c.Stats()
	t.Logf("client dropped %d, server dropped %d datagrams; stats %+v", lossyClient.droppedCount(), lossyServer.droppedCount(), st)
	if st.PacketsLost == 0 {
		t.Fatalf("no losses detected despite a lossy link")
	}
}

func TestRetry(t *testing.T) {
	l := echoServer(t, nil, &Config{RequireAddressValidation: true})
	c := dial(t, l.Addr().String(), nil)
	if !c.ConnectionState().UsedRetry {
		t.Fatalf("Retry was not used")
	}
	if got := echoStream(t, c, []byte("after retry")); string(got) != "after retry" {
		t.Fatalf("echo = %q", got)
	}
}

func TestCertificateFailure(t *testing.T) {
	l := echoServer(t, nil, nil)
	tc := clientTLS(t)
	tc.RootCAs = x509.NewCertPool() // trusts nothing
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, l.Addr().String(), tc, nil)
	var te *TransportError
	if !errors.As(err, &te) || !te.Code.IsCryptoError() || te.Remote {
		t.Fatalf("got %v", err)
	}
	var ae *tls13.AlertError
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &ae) || ae.Alert != tls13.AlertUnknownCA || !errors.As(err, &ua) {
		t.Fatalf("TLS cause not exposed: %v", err)
	}
}

func TestALPNMismatch(t *testing.T) {
	l := echoServer(t, nil, nil)
	tc := clientTLS(t)
	tc.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, l.Addr().String(), tc, nil)
	var te *TransportError
	if !errors.As(err, &te) || !te.Remote || te.Code != cryptoErrorBase+TransportErrorCode(tls13.AlertNoApplicationProtocol) {
		t.Fatalf("got %v", err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	// A UDP socket that never answers, like a firewall dropping packets.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	start := time.Now()
	_, err = Dial(context.Background(), pc.LocalAddr().String(), clientTLS(t), &Config{HandshakeTimeout: 700 * time.Millisecond})
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %v", d)
	}
}

func TestVersionNegotiation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2000)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		hdr, err := parseLongHeader(buf[:n])
		if err != nil {
			return
		}
		vn := []byte{0x80, 0, 0, 0, 0}
		vn = append(vn, byte(len(hdr.scid)))
		vn = append(vn, hdr.scid...)
		vn = append(vn, byte(len(hdr.dcid)))
		vn = append(vn, hdr.dcid...)
		vn = append(vn, 0x6b, 0x33, 0x43, 0xcf) // QUIC v2 only
		pc.WriteTo(vn, addr)
	}()
	_, err = Dial(context.Background(), pc.LocalAddr().String(), clientTLS(t), &Config{HandshakeTimeout: 3 * time.Second})
	var vne *VersionNegotiationError
	if !errors.As(err, &vne) || len(vne.Offered) != 1 || vne.Offered[0] != 0x6b3343cf {
		t.Fatalf("got %v", err)
	}
}

func TestServerVersionNegotiation(t *testing.T) {
	l := echoServer(t, nil, nil)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pkt := []byte{0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 4, 9, 9, 9, 9}
	pkt = append(pkt, make([]byte, 1200-len(pkt))...)
	pc.WriteTo(pkt, l.Addr())
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := parseLongHeader(buf[:n])
	if err != nil || hdr.version != 0 || len(hdr.versions) != 1 || hdr.versions[0] != version1 ||
		!bytes.Equal(hdr.dcid, []byte{9, 9, 9, 9}) {
		t.Fatalf("bad Version Negotiation: %x (%v)", buf[:n], err)
	}
}

func TestKeyUpdate(t *testing.T) {
	l := echoServer(t, nil, nil)
	c := dial(t, l.Addr().String(), nil)
	echoStream(t, c, []byte("confirm the handshake"))
	for i := 0; i < 3; i++ {
		if err := c.UpdateKeys(); err != nil {
			t.Fatalf("key update %d refused: %v", i, err)
		}
		data := randomBytes(200_000)
		if got := echoStream(t, c, data); !bytes.Equal(got, data) {
			t.Fatalf("echo after key update %d failed", i)
		}
		c.mu.Lock()
		phases := c.readPhase == c.writePhase
		c.mu.Unlock()
		if !phases {
			t.Fatalf("peer did not follow the key update")
		}
	}
}

func TestIdleTimeoutAndKeepAlive(t *testing.T) {
	l := echoServer(t, nil, nil)
	c := dial(t, l.Addr().String(), &Config{MaxIdleTimeout: 1200 * time.Millisecond})
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not time out")
	}
	if !errors.Is(c.Err(), ErrIdleTimeout) {
		t.Fatalf("err = %v", c.Err())
	}

	k := dial(t, l.Addr().String(), &Config{MaxIdleTimeout: 1200 * time.Millisecond, KeepAlivePeriod: 300 * time.Millisecond})
	select {
	case <-k.Done():
		t.Fatalf("keep-alive connection closed: %v", k.Err())
	case <-time.After(3 * time.Second):
	}
	if got := echoStream(t, k, []byte("still alive")); string(got) != "still alive" {
		t.Fatalf("echo = %q", got)
	}
}

func TestStreamResetAndStopSending(t *testing.T) {
	l, err := Listen("127.0.0.1:0", serverTLS(t), &Config{Logf: testLogf(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serverErrs := make(chan error, 2)
	go func() {
		c, err := l.Accept(context.Background())
		if err != nil {
			return
		}
		// Stream 1: the client resets it; the server's Read must fail.
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			serverErrs <- err
			return
		}
		_, err = io.ReadAll(s)
		serverErrs <- err
		// Stream 2: the server stops reading; the client's writes fail.
		s2, err := c.AcceptStream(context.Background())
		if err != nil {
			serverErrs <- err
			return
		}
		buf := make([]byte, 10)
		io.ReadFull(s2, buf)
		s2.CancelRead(77)
		serverErrs <- nil
		<-c.Done()
	}()

	c := dial(t, l.Addr().String(), nil)
	s, _ := c.OpenStreamSync(context.Background())
	s.Write([]byte("partial"))
	time.Sleep(50 * time.Millisecond)
	s.CancelWrite(42)
	var se *StreamError
	if err := <-serverErrs; !errors.As(err, &se) || se.Code != 42 || !se.Remote {
		t.Fatalf("server read error = %v", err)
	}

	s2, _ := c.OpenStreamSync(context.Background())
	s2.SetWriteDeadline(time.Now().Add(10 * time.Second))
	<-func() chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			chunk := make([]byte, 64<<10)
			for {
				if _, err := s2.Write(chunk); err != nil {
					if !errors.As(err, &se) || se.Code != 77 || !se.Remote {
						t.Errorf("client write error = %v", err)
					}
					return
				}
			}
		}()
		return done
	}()
	<-serverErrs
}

func TestApplicationClose(t *testing.T) {
	l, err := Listen("127.0.0.1:0", serverTLS(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept(context.Background())
		if err == nil {
			c.CloseWithError(0x42, "goodbye")
		}
	}()
	c := dial(t, l.Addr().String(), nil)
	_, err = c.AcceptStream(context.Background())
	var ae *ApplicationError
	if !errors.As(err, &ae) || ae.Code != 0x42 || ae.Reason != "goodbye" || !ae.Remote {
		t.Fatalf("got %v", err)
	}
}

func TestUniStreams(t *testing.T) {
	l, err := Listen("127.0.0.1:0", serverTLS(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept(context.Background())
		if err != nil {
			return
		}
		s, err := c.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		b, _ := io.ReadAll(s)
		got <- b
		if _, err := s.Write([]byte("x")); err == nil {
			t.Errorf("write on a receive-only stream succeeded")
		}
	}()
	c := dial(t, l.Addr().String(), nil)
	s, err := c.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("one way"))
	s.Close()
	select {
	case b := <-got:
		if string(b) != "one way" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatalf("read on a send-only stream succeeded")
	}
}
