package dns

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config describes how to resolve names, normally read from
// /etc/resolv.conf.
type Config struct {
	// Servers lists DNS servers in preference order. Each entry is either a
	// bare "ip[:port]" (cleartext UDP, falling back to TCP on truncation)
	// or a scheme-prefixed encrypted transport understood by parseServer:
	// udp://, tcp://, tls:// (DoT), https:// (DoH) or quic:// (DoQ).
	Servers  []string
	Search   []string
	Ndots    int
	Timeout  time.Duration // per exchange
	Attempts int
	// HostsFile is consulted before DNS if set (normally /etc/hosts).
	HostsFile string

	// TLSRoots is the trust anchor set for the certificates of DoT, DoH and
	// DoQ servers. A nil pool uses the system roots.
	TLSRoots *x509.CertPool
	// TLSInsecureSkipVerify disables certificate verification for encrypted
	// transports. For diagnostics only.
	TLSInsecureSkipVerify bool
}

// DefaultConfig reads /etc/resolv.conf, falling back to a local resolver
// on 127.0.0.1:53 like the Go and glibc resolvers do.
func DefaultConfig() *Config {
	cfg, err := ReadResolvConf("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		cfg = &Config{Servers: []string{"127.0.0.1:53"}, Ndots: 1, Timeout: 5 * time.Second, Attempts: 2}
	}
	cfg.HostsFile = "/etc/hosts"
	return cfg
}

// ReadResolvConf parses a resolv.conf file.
func ReadResolvConf(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg := &Config{Ndots: 1, Timeout: 5 * time.Second, Attempts: 2}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				cfg.Servers = append(cfg.Servers, netip.AddrPortFrom(ip, 53).String())
			}
		case "search":
			cfg.Search = append([]string(nil), fields[1:]...)
		case "domain":
			cfg.Search = []string{fields[1]}
		case "options":
			for _, o := range fields[1:] {
				k, v, _ := strings.Cut(o, ":")
				n, err := strconv.Atoi(v)
				if err != nil {
					continue
				}
				switch k {
				case "ndots":
					cfg.Ndots = min(max(n, 0), 15)
				case "timeout":
					cfg.Timeout = time.Duration(min(max(n, 1), 30)) * time.Second
				case "attempts":
					cfg.Attempts = min(max(n, 1), 5)
				}
			}
		}
	}
	return cfg, sc.Err()
}

// ErrorKind classifies a lookup failure.
type ErrorKind string

const (
	ErrNXDomain  ErrorKind = "nxdomain"  // the name does not exist
	ErrNoData    ErrorKind = "nodata"    // the name exists but has no A/AAAA records
	ErrServFail  ErrorKind = "servfail"  // the resolver failed (often DNSSEC or upstream trouble)
	ErrRefused   ErrorKind = "refused"   // the resolver refused to answer
	ErrTimeout   ErrorKind = "timeout"   // no server answered
	ErrNetwork   ErrorKind = "network"   // queries could not be sent
	ErrMalformed ErrorKind = "malformed" // answers could not be parsed
	ErrOther     ErrorKind = "other"
)

// Error is a lookup failure.
type Error struct {
	Kind   ErrorKind
	Name   string
	Server string
	Err    error
}

func (e *Error) Error() string {
	var what string
	switch e.Kind {
	case ErrNXDomain:
		what = "no such host (NXDOMAIN)"
	case ErrNoData:
		what = "no A/AAAA records (NOERROR, empty answer)"
	case ErrServFail:
		what = "server failure (SERVFAIL)"
	case ErrRefused:
		what = "query refused (REFUSED)"
	case ErrTimeout:
		what = "no response from DNS servers"
	case ErrNetwork:
		what = "cannot reach DNS servers"
	case ErrMalformed:
		what = "malformed response"
	default:
		what = "lookup failed"
	}
	msg := fmt.Sprintf("lookup %s: %s", e.Name, what)
	if e.Server != "" {
		msg += " from " + e.Server
	}
	if e.Err != nil && e.Kind != ErrNXDomain && e.Kind != ErrNoData {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// Exchange records one query sent to one server.
type Exchange struct {
	Server string
	Proto  string // "udp" or "tcp"
	Name   string
	Type   Type
	RTT    time.Duration
	RCode  RCode
	Err    error
}

// Result is a successful lookup.
type Result struct {
	Name      string // the name that resolved (after search list expansion)
	Canonical string // end of the CNAME chain
	CNAMEs    []string
	Addrs     []netip.Addr
	Source    string // "hosts" or the server that answered
	Exchanges []Exchange
}

// Client resolves names. It is safe for concurrent use.
type Client struct {
	Config *Config
	// Dial, if set, replaces net.Dialer for reaching servers (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// LookupHost resolves host to IPv4 and IPv6 addresses.
func (c *Client) LookupHost(ctx context.Context, host string) (*Result, error) {
	cfg := c.Config
	host = strings.TrimSuffix(host, ".")
	if addrs := lookupHostsFile(cfg.HostsFile, host); len(addrs) > 0 {
		return &Result{Name: host, Canonical: host, Addrs: addrs, Source: "hosts"}, nil
	}
	if len(cfg.Servers) == 0 {
		return nil, &Error{Kind: ErrNetwork, Name: host, Err: errors.New("no DNS servers configured")}
	}
	var exchanges []Exchange
	var best *Error
	for _, name := range c.candidates(host) {
		res, err := c.lookupName(ctx, name)
		exchanges = append(exchanges, res.Exchanges...)
		if err == nil {
			res.Exchanges = exchanges
			return res, nil
		}
		var e *Error
		if !errors.As(err, &e) {
			return nil, err
		}
		if best == nil || severity(e.Kind) < severity(best.Kind) {
			best = e
		}
		if ctx.Err() != nil {
			break
		}
	}
	best.Name = host
	return &Result{Name: host, Exchanges: exchanges}, best
}

// severity orders errors by how informative they are: an authoritative
// "exists but empty" beats NXDOMAIN, which beats server trouble.
func severity(k ErrorKind) int {
	switch k {
	case ErrNoData:
		return 0
	case ErrNXDomain:
		return 1
	case ErrServFail, ErrRefused:
		return 2
	case ErrMalformed:
		return 3
	case ErrTimeout:
		return 4
	}
	return 5
}

// candidates applies the search list (resolv.conf(5) semantics).
func (c *Client) candidates(host string) []string {
	cfg := c.Config
	if len(cfg.Search) == 0 {
		return []string{host}
	}
	var withSearch []string
	for _, s := range cfg.Search {
		withSearch = append(withSearch, host+"."+strings.TrimSuffix(s, "."))
	}
	if strings.Count(host, ".") >= cfg.Ndots {
		return append([]string{host}, withSearch...)
	}
	return append(withSearch, host)
}

// lookupName queries A and AAAA for a single fully qualified name.
func (c *Client) lookupName(ctx context.Context, name string) (*Result, error) {
	type answer struct {
		msg *Message
		ex  []Exchange
		err error
	}
	var wg sync.WaitGroup
	results := make([]answer, 2)
	for i, t := range []Type{TypeA, TypeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, ex, err := c.query(ctx, name, t)
			results[i] = answer{m, ex, err}
		}()
	}
	wg.Wait()

	res := &Result{Name: name, Canonical: name}
	for _, r := range results {
		res.Exchanges = append(res.Exchanges, r.ex...)
	}
	var errs []*Error
	for i, r := range results {
		if r.err != nil {
			var e *Error
			if errors.As(r.err, &e) {
				errs = append(errs, e)
				continue
			}
			return res, r.err
		}
		canon, chain, addrs := r.msg.addresses(name, []Type{TypeA, TypeAAAA}[i])
		if len(chain) > len(res.CNAMEs) {
			res.CNAMEs, res.Canonical = chain, canon
		}
		res.Addrs = append(res.Addrs, addrs...)
		if res.Source == "" {
			res.Source = r.ex[len(r.ex)-1].Server
		}
	}
	if len(res.Addrs) > 0 {
		return res, nil
	}
	if len(errs) == 0 {
		return res, &Error{Kind: ErrNoData, Name: name, Server: res.Source}
	}
	best := errs[0]
	for _, e := range errs[1:] {
		if severity(e.Kind) < severity(best.Kind) {
			best = e
		}
	}
	if best.Kind == ErrNXDomain && len(errs) == 1 {
		// One family is NXDOMAIN while the other succeeded empty: a
		// broken server; report the empty answer.
		return res, &Error{Kind: ErrNoData, Name: name, Server: best.Server}
	}
	return res, best
}

// query asks the configured servers in turn until one gives a usable
// answer (NOERROR or NXDOMAIN).
func (c *Client) query(ctx context.Context, name string, qtype Type) (*Message, []Exchange, error) {
	cfg := c.Config
	attempts := max(cfg.Attempts, 1)
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var exchanges []Exchange
	var lastErr *Error
	for a := 0; a < attempts; a++ {
		for _, server := range cfg.Servers {
			if ctx.Err() != nil {
				return nil, exchanges, &Error{Kind: ErrTimeout, Name: name, Err: ctx.Err()}
			}
			spec, err := parseServer(server)
			if err != nil {
				lastErr = &Error{Kind: ErrNetwork, Name: name, Server: server, Err: err}
				continue
			}
			m, ex := c.exchange(ctx, spec, name, qtype, timeout)
			exchanges = append(exchanges, ex)
			if ex.Err == nil && m.Truncated && spec.scheme == "udp" {
				// Retry over TCP for the full answer (RFC 7766).
				tcpSpec := spec
				tcpSpec.scheme = "tcp"
				m, ex = c.exchange(ctx, tcpSpec, name, qtype, timeout)
				exchanges = append(exchanges, ex)
			}
			if ex.Err != nil {
				lastErr = classifyNetError(name, server, ex.Err)
				continue
			}
			switch m.RCode {
			case RCodeSuccess:
				return m, exchanges, nil
			case RCodeNXDomain:
				return nil, exchanges, &Error{Kind: ErrNXDomain, Name: name, Server: server}
			case RCodeServFail:
				lastErr = &Error{Kind: ErrServFail, Name: name, Server: server}
			case RCodeRefused:
				lastErr = &Error{Kind: ErrRefused, Name: name, Server: server}
			default:
				lastErr = &Error{Kind: ErrOther, Name: name, Server: server, Err: fmt.Errorf("server answered %v", m.RCode)}
			}
		}
		if lastErr != nil && (lastErr.Kind == ErrServFail || lastErr.Kind == ErrRefused) {
			break // every server answered; retrying will not help
		}
	}
	return nil, exchanges, lastErr
}

func classifyNetError(name, server string, err error) *Error {
	var ne net.Error
	switch {
	case errors.Is(err, errMalformed) || errors.Is(err, errMismatch):
		return &Error{Kind: ErrMalformed, Name: name, Server: server, Err: err}
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return &Error{Kind: ErrTimeout, Name: name, Server: server, Err: err}
	}
	return &Error{Kind: ErrNetwork, Name: name, Server: server, Err: err}
}

var errMismatch = errors.New("response does not match the query")

func (c *Client) exchange(ctx context.Context, spec serverSpec, name string, qtype Type, timeout time.Duration) (*Message, Exchange) {
	ex := Exchange{Server: spec.display, Proto: spec.scheme, Name: name, Type: qtype}
	start := time.Now()
	m, err := c.roundTrip(ctx, spec, name, qtype, timeout)
	ex.RTT = time.Since(start)
	ex.Err = err
	if m != nil {
		ex.RCode = m.RCode
	}
	return m, ex
}

func (c *Client) roundTrip(ctx context.Context, spec serverSpec, name string, qtype Type, timeout time.Duration) (*Message, error) {
	// DoH and DoQ recommend a zero message ID (RFC 8484 §4.1, RFC 9250
	// §4.2.1); the other transports use a random ID to match replies.
	var id uint16
	if !(spec.scheme == "https" || spec.scheme == "quic") {
		var idb [2]byte
		rand.Read(idb[:])
		id = binary.BigEndian.Uint16(idb[:])
	}
	query, err := buildQuery(id, name, qtype)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch spec.scheme {
	case "tls":
		return c.roundTripDoT(ctx, spec, id, query, name, qtype)
	case "https":
		return c.roundTripDoH(ctx, spec, query, name, qtype)
	case "quic":
		return c.roundTripDoQ(ctx, spec, query, name, qtype)
	}

	conn, err := c.rawDial(ctx, spec.scheme, spec.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	if spec.scheme == "tcp" {
		if err := writePrefixed(conn, query); err != nil {
			return nil, err
		}
		resp, err := readPrefixed(conn)
		if err != nil {
			return nil, err
		}
		return checkResponse(resp, id, name, qtype)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		m, err := checkResponse(buf[:n], id, name, qtype)
		if errors.Is(err, errMismatch) {
			continue // stray or spoofed datagram: keep waiting
		}
		return m, err
	}
}

func checkResponse(b []byte, id uint16, name string, qtype Type) (*Message, error) {
	m, err := parseMessage(b)
	if err != nil {
		return nil, err
	}
	if m.ID != id || !m.Response {
		return nil, errMismatch
	}
	if m.RCode != RCodeFormErr && (!strings.EqualFold(m.QName, strings.TrimSuffix(name, ".")) || m.QType != qtype) {
		return nil, errMismatch
	}
	return m, nil
}

func lookupHostsFile(path, host string) []netip.Addr {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, h := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(h, "."), host) {
				out = append(out, ip.Unmap())
				break
			}
		}
	}
	return out
}
