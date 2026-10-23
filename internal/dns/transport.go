package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// Encrypted DNS transports. Plain DNS (UDP/TCP on port 53) travels in the
// clear, so an on-path resolver or middlebox can read every query and forge
// or drop the answer. The encrypted transports below carry the same DNS
// wire format over an authenticated channel, so a network that tampers with
// plaintext DNS can no longer see or rewrite the lookup:
//
//   - DoT, DNS over TLS         (RFC 7858), default port 853
//   - DoH, DNS over HTTPS       (RFC 8484), default path /dns-query
//   - DoQ, DNS over QUIC        (RFC 9250), default port 853
//
// DoT and DoH run over this repository's TLS 1.3 implementation; DoQ runs
// over its QUIC implementation.

// serverSpec is a parsed DNS server address. A plain "ip[:port]" means
// cleartext UDP; a scheme selects an encrypted transport.
type serverSpec struct {
	scheme   string // udp, tcp, tls, https, quic
	addr     string // host:port to dial
	hostname string // TLS server name / certificate name (tls, https, quic)
	url      string // full request URL (https only)
	display  string // the spec as the user wrote it, for reports
}

func (s serverSpec) encrypted() bool {
	return s.scheme == "tls" || s.scheme == "https" || s.scheme == "quic"
}

// parseServer parses a DNS server specification:
//
//	1.1.1.1                       cleartext UDP (port 53), TCP on truncation
//	udp://1.1.1.1  tcp://1.1.1.1  cleartext, explicit transport
//	tls://1.1.1.1#cloudflare-dns.com    DoT (port 853), with a server name
//	quic://dns.adguard.com              DoQ (port 853)
//	https://cloudflare-dns.com/dns-query DoH
//
// The optional "#name" after a tls:// or quic:// authority is the name used
// for certificate verification, which is needed when the server is given by
// IP address.
func parseServer(s string) (serverSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return serverSpec{}, errors.New("empty DNS server")
	}
	spec := serverSpec{display: s}
	scheme, rest, hasScheme := strings.Cut(s, "://")
	if !hasScheme {
		scheme, rest = "udp", s
	}
	spec.scheme = scheme

	switch scheme {
	case "udp", "tcp":
		spec.addr = withDefaultPort(rest, "53")
	case "tls", "quic":
		authority, name, _ := strings.Cut(rest, "#")
		port := "853"
		spec.addr = withDefaultPort(authority, port)
		spec.hostname = name
		if spec.hostname == "" {
			spec.hostname = hostOnly(authority)
		}
	case "https", "http":
		if scheme == "http" {
			return serverSpec{}, errors.New("DoH requires https://")
		}
		u, err := url.Parse(s)
		if err != nil {
			return serverSpec{}, fmt.Errorf("invalid DoH URL %q: %w", s, err)
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		spec.url = u.String()
		spec.hostname = u.Hostname()
		spec.addr = net.JoinHostPort(u.Hostname(), portOr(u.Port(), "443"))
	default:
		return serverSpec{}, fmt.Errorf("unknown DNS transport %q", scheme)
	}
	return spec, nil
}

func withDefaultPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), port)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func portOr(got, def string) string {
	if got != "" {
		return got
	}
	return def
}

func (c *Client) rawDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (c *Client) tlsConfig(spec serverSpec, alpn ...string) *tls13.Config {
	return &tls13.Config{
		ServerName:         spec.hostname,
		RootCAs:            c.Config.TLSRoots,
		InsecureSkipVerify: c.Config.TLSInsecureSkipVerify,
		NextProtos:         alpn,
	}
}

// writePrefixed writes a DNS message with the two-byte length prefix used by
// DNS over TCP, DoT and DoQ (RFC 1035 §4.2.2, RFC 7858, RFC 9250).
func writePrefixed(w io.Writer, msg []byte) error {
	framed := binary.BigEndian.AppendUint16(make([]byte, 0, len(msg)+2), uint16(len(msg)))
	_, err := w.Write(append(framed, msg...))
	return err
}

// readPrefixed reads a length-prefixed DNS message.
func readPrefixed(r io.Reader) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// roundTripDoT performs one query over DNS over TLS.
func (c *Client) roundTripDoT(ctx context.Context, spec serverSpec, id uint16, query []byte, name string, qtype Type) (*Message, error) {
	raw, err := c.rawDial(ctx, "tcp", spec.addr)
	if err != nil {
		return nil, err
	}
	conn := tls13.Client(raw, c.tlsConfig(spec))
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := writePrefixed(conn, query); err != nil {
		return nil, err
	}
	resp, err := readPrefixed(conn)
	if err != nil {
		return nil, err
	}
	return checkResponse(resp, id, name, qtype)
}

// roundTripDoQ performs one query over DNS over QUIC. The DNS message ID
// must be 0 (RFC 9250 §4.2.1); the stream provides the correlation.
func (c *Client) roundTripDoQ(ctx context.Context, spec serverSpec, query []byte, name string, qtype Type) (*Message, error) {
	conn, err := quic.Dial(ctx, spec.addr, c.tlsConfig(spec, "doq"), &quic.Config{HandshakeTimeout: timeoutFrom(ctx)})
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		stream.SetDeadline(dl)
	}
	if err := writePrefixed(stream, query); err != nil {
		return nil, err
	}
	stream.Close() // half-close: one query per stream
	resp, err := readPrefixed(stream)
	if err != nil {
		return nil, err
	}
	return checkResponse(resp, 0, name, qtype)
}

// roundTripDoH performs one query over DNS over HTTPS (RFC 8484), using the
// POST method with a dns-message body.
func (c *Client) roundTripDoH(ctx context.Context, spec serverSpec, query []byte, name string, qtype Type) (*Message, error) {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       c.rawDial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := c.rawDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := tls13.Client(raw, c.tlsConfig(spec, "http/1.1"))
			if dl, ok := ctx.Deadline(); ok {
				conn.SetDeadline(dl)
			}
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "wheel-dns/1.0")

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned HTTP %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
		return nil, fmt.Errorf("DoH server returned unexpected Content-Type %q", ct)
	}
	return checkResponse(body, 0, name, qtype)
}

func timeoutFrom(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			return d
		}
	}
	return 5 * time.Second
}
