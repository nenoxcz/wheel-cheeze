// Command wheelcat is a netcat for encrypted transports: it connects to or
// listens on TLS 1.3 (over TCP) or QUIC, using this repository's own
// implementations, and copies stdin/stdout over the connection.
//
//	wheelcat -l -echo :4433              # TLS 1.3 echo server
//	wheelcat -insecure localhost:4433    # client
//	wheelcat -l -quic -echo :4433        # QUIC echo server
//	wheelcat -quic -insecure localhost:4433
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

var (
	listen    = flag.Bool("l", false, "listen for connections instead of connecting")
	useQUIC   = flag.Bool("quic", false, "use QUIC (UDP) instead of TLS 1.3 over TCP")
	echo      = flag.Bool("echo", false, "server: echo data back to every client instead of using stdin/stdout")
	alpn      = flag.String("alpn", "wheelcat", "comma-separated ALPN protocols")
	insecure  = flag.Bool("insecure", false, "client: do not verify the server certificate")
	caFile    = flag.String("cacert", "", "client: PEM file with CA certificates to trust")
	sni       = flag.String("sni", "", "client: server name (default: host from the address)")
	certFile  = flag.String("cert", "", "server: PEM certificate chain (default: generate a self-signed one)")
	keyFile   = flag.String("key", "", "server: PEM private key")
	writeCert = flag.String("write-cert", "", "server: save the generated self-signed certificate to this file")
	keyLog    = flag.String("keylog", "", "append TLS secrets to this file in NSS key log format (for Wireshark)")
	verbose   = flag.Bool("v", false, "print handshake details and a QUIC event trace to stderr")
	timeout   = flag.Duration("timeout", 10*time.Second, "connection establishment timeout")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wheelcat [flags] host:port\n       wheelcat -l [flags] [host]:port\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	log.SetFlags(0)
	log.SetPrefix("wheelcat: ")

	tlsConf := &tls13.Config{NextProtos: strings.Split(*alpn, ",")}
	if *keyLog != "" {
		f, err := os.OpenFile(*keyLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		tlsConf.KeyLogWriter = f
	}
	var quicConf quic.Config
	if *verbose {
		quicConf.Logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, "  quic "+format+"\n", args...) }
	}

	var err error
	if *listen {
		err = serve(flag.Arg(0), tlsConf, &quicConf)
	} else {
		err = connect(flag.Arg(0), tlsConf, &quicConf)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// halfCloser is a connection whose write side can be closed separately.
type halfCloser interface {
	io.ReadWriter
	CloseWrite() error
}

// quicStream adapts a QUIC stream (whose Close only ends the send side).
type quicStream struct{ *quic.Stream }

func (s quicStream) CloseWrite() error { return s.Stream.Close() }

// pipe copies stdin to conn and conn to stdout until both directions end.
func pipe(conn halfCloser) error {
	go func() {
		io.Copy(conn, os.Stdin)
		conn.CloseWrite()
	}()
	_, err := io.Copy(os.Stdout, conn)
	return err
}

func connect(addr string, tlsConf *tls13.Config, quicConf *quic.Config) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	tlsConf.ServerName = host
	if *sni != "" {
		tlsConf.ServerName = *sni
	}
	tlsConf.InsecureSkipVerify = *insecure
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		tlsConf.RootCAs = x509.NewCertPool()
		if !tlsConf.RootCAs.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates in %s", *caFile)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	if *useQUIC {
		quicConf.HandshakeTimeout = *timeout
		c, err := quic.Dial(ctx, addr, tlsConf, quicConf)
		if err != nil {
			return err
		}
		defer c.Close()
		st := c.ConnectionState()
		describe("QUIC v1", c.RemoteAddr(), st.TLS, time.Since(start))
		if *verbose {
			fmt.Fprintf(os.Stderr, "  rtt %v, retry %v\n", c.Stats().SmoothedRTT, st.UsedRetry)
		}
		s, err := c.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		return pipe(quicStream{s})
	}

	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c := tls13.Client(raw, tlsConf)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return err
	}
	defer c.Close()
	describe("TLS 1.3 over TCP", c.RemoteAddr(), c.ConnectionState(), time.Since(start))
	return pipe(c)
}

func describe(proto string, remote net.Addr, st tls13.ConnectionState, took time.Duration) {
	elapsed := ""
	if took > 0 {
		elapsed = fmt.Sprintf(" in %v", took.Round(time.Microsecond))
	}
	fmt.Fprintf(os.Stderr, "connected to %v: %s, %s, %v, ALPN %q%s\n",
		remote, proto, tls13.CipherSuiteName(st.CipherSuite), st.CurveID, st.NegotiatedProtocol, elapsed)
	if !*verbose {
		return
	}
	if st.DidHelloRetryRequest {
		fmt.Fprintln(os.Stderr, "  server sent a HelloRetryRequest")
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		fmt.Fprintf(os.Stderr, "  certificate %q issued by %q, expires %s, signature %v\n",
			leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter.Format(time.DateOnly), st.SignatureScheme)
	}
	if len(st.VerifiedChains) == 0 {
		fmt.Fprintln(os.Stderr, "  certificate NOT verified (-insecure)")
	}
}

func serverCertificate(addr string) (tls13.Certificate, error) {
	if *certFile != "" || *keyFile != "" {
		return tls13.LoadX509KeyPair(*certFile, *keyFile)
	}
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, _, err := net.SplitHostPort(addr); err == nil && h != "" && !slices.Contains(hosts, h) {
		hosts = append(hosts, h)
	}
	if name, err := os.Hostname(); err == nil && !slices.Contains(hosts, name) {
		hosts = append(hosts, name)
	}
	cert, err := tls13.GenerateSelfSigned(hosts, 30*24*time.Hour)
	if err != nil {
		return cert, err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	fmt.Fprintf(os.Stderr, "generated a self-signed certificate for %s\n  SHA-256 fingerprint %X\n", strings.Join(hosts, ", "), sum)
	if *writeCert != "" {
		certPEM, _, err := cert.MarshalPEM()
		if err != nil {
			return cert, err
		}
		if err := os.WriteFile(*writeCert, certPEM, 0o644); err != nil {
			return cert, err
		}
		fmt.Fprintf(os.Stderr, "  saved to %s (use it with -cacert)\n", *writeCert)
	}
	return cert, nil
}

func serve(addr string, tlsConf *tls13.Config, quicConf *quic.Config) error {
	cert, err := serverCertificate(addr)
	if err != nil {
		return err
	}
	tlsConf.Certificates = []tls13.Certificate{cert}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *useQUIC {
		l, err := quic.Listen(addr, tlsConf, quicConf)
		if err != nil {
			return err
		}
		defer l.Close()
		fmt.Fprintf(os.Stderr, "listening on %v (QUIC)\n", l.Addr())
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			describe("QUIC v1", c.RemoteAddr(), c.ConnectionState().TLS, 0)
			if !*echo {
				s, err := c.AcceptStream(ctx)
				if err != nil {
					return err
				}
				err = pipe(quicStream{s})
				c.Close()
				return err
			}
			go func() {
				for {
					s, err := c.AcceptStream(context.Background())
					if err != nil {
						fmt.Fprintf(os.Stderr, "%v disconnected: %v\n", c.RemoteAddr(), err)
						return
					}
					go func() {
						io.Copy(s, s)
						s.Close()
					}()
				}
			}()
		}
	}

	l, err := tls13.Listen("tcp", addr, tlsConf)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	fmt.Fprintf(os.Stderr, "listening on %v (TLS 1.3 over TCP)\n", l.Addr())
	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		c := nc.(*tls13.Conn)
		hctx, cancel := context.WithTimeout(ctx, *timeout)
		err = c.HandshakeContext(hctx)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "handshake with %v failed: %v\n", c.RemoteAddr(), err)
			c.Close()
			continue
		}
		describe("TLS 1.3 over TCP", c.RemoteAddr(), c.ConnectionState(), 0)
		if !*echo {
			err = pipe(c)
			c.Close()
			return err
		}
		go func() {
			defer c.Close()
			io.Copy(c, c)
		}()
	}
}
