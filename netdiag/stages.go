package netdiag

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/nenoxcz/wheel-cheeze/internal/dns"
	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// DNS

func diagDNS(ctx context.Context, t *target, opts *Options) (_ []net.IP, res Result) {
	res = Result{Stage: StageDNS}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	if ip := net.ParseIP(t.host); ip != nil {
		res.Status = StatusSkipped
		res.Summary = "target is an IP address; no lookup needed"
		return []net.IP{ip}, res
	}

	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	var addrs []netip.Addr
	if opts.SystemResolver {
		got, err := net.DefaultResolver.LookupNetIP(ctx, "ip", t.host)
		if err != nil {
			fillSystemDNSError(&res, t.host, err)
			return nil, res
		}
		addrs = got
		res.Summary = fmt.Sprintf("%s -> %s", t.host, joinAddrs(addrs, 4))
		res.Details = append(res.Details, "resolved by the system resolver")
	} else {
		cfg := dns.DefaultConfig()
		switch opts.HostsFile {
		case "":
		case "-":
			cfg.HostsFile = ""
		default:
			cfg.HostsFile = opts.HostsFile
		}
		if opts.DNSServer != "" {
			cfg.Servers = []string{normalizeDNSServer(opts.DNSServer)}
			cfg.Search = nil
		}
		cfg.TLSRoots = opts.RootCAs
		cfg.TLSInsecureSkipVerify = opts.InsecureSkipVerify
		cfg.Timeout = min(cfg.Timeout, max(opts.timeout()/2, 200*time.Millisecond))
		client := &dns.Client{Config: cfg}
		lr, err := client.LookupHost(ctx, t.host)
		if lr != nil {
			res.Details = append(res.Details, exchangeDetails(lr.Exchanges)...)
		}
		if err != nil {
			fillDNSError(&res, err, cfg.Servers)
			return nil, res
		}
		addrs = lr.Addrs
		res.Summary = fmt.Sprintf("%s -> %s", t.host, joinAddrs(addrs, 4))
		if transport := dnsTransportName(lr.Source); transport != "" {
			res.Details = append([]string{"resolved over " + transport}, res.Details...)
		}
		if lr.Name != t.host {
			res.Details = append([]string{"resolved as " + lr.Name + " (search list)"}, res.Details...)
		}
		if len(lr.CNAMEs) > 0 {
			res.Details = append([]string{"CNAME chain: " + strings.Join(append([]string{lr.Name}, lr.CNAMEs...), " -> ")}, res.Details...)
		}
		if lr.Source == "hosts" {
			res.Details = append(res.Details, "answered from the hosts file")
		}
	}

	var ips []net.IP
	for _, a := range addrs {
		a = a.Unmap()
		if (opts.Network == "ip4" && !a.Is4()) || (opts.Network == "ip6" && !a.Is6()) {
			continue
		}
		ips = append(ips, net.IP(a.AsSlice()))
	}
	if len(ips) == 0 {
		family := "IPv4"
		if opts.Network == "ip6" {
			family = "IPv6"
		}
		res.Status = StatusFail
		res.Code = "dns.no_" + strings.ToLower(family)
		res.Summary = fmt.Sprintf("%s has no %s address (only %s)", t.host, family, joinAddrs(addrs, 4))
		res.Hint = "drop the -4/-6 restriction or publish the missing A/AAAA record"
		return nil, res
	}
	res.Status = StatusOK
	return ips, res
}

// normalizeDNSServer adds a default port to a bare "ip" server, and leaves
// scheme-prefixed encrypted-DNS specs (tls://, https://, quic://, ...)
// untouched.
func normalizeDNSServer(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return net.JoinHostPort(strings.Trim(s, "[]"), "53")
	}
	return s
}

// dnsTransportName names the encrypted transport that answered, for the DNS
// stage details. Plaintext UDP, the default, gets no note.
func dnsTransportName(source string) string {
	switch {
	case strings.HasPrefix(source, "tls://"):
		return "DoT (DNS over TLS): " + source
	case strings.HasPrefix(source, "https://"):
		return "DoH (DNS over HTTPS): " + source
	case strings.HasPrefix(source, "quic://"):
		return "DoQ (DNS over QUIC): " + source
	case strings.HasPrefix(source, "tcp://"):
		return "cleartext TCP: " + source
	}
	return ""
}

func joinAddrs(addrs []netip.Addr, limit int) string {
	var s []string
	for i, a := range addrs {
		if i == limit {
			s = append(s, fmt.Sprintf("(+%d more)", len(addrs)-limit))
			break
		}
		s = append(s, a.Unmap().String())
	}
	return strings.Join(s, ", ")
}

// exchangeLabel names a query's server, appending the transport only when
// it is not already evident from a scheme in the server string.
func exchangeLabel(ex dns.Exchange) string {
	if strings.Contains(ex.Server, "://") {
		return ex.Server
	}
	return ex.Server + "/" + ex.Proto
}

// exchangeDetails summarizes the queries that did not simply succeed.
func exchangeDetails(exs []dns.Exchange) []string {
	var out []string
	answered := ""
	for _, ex := range exs {
		if ex.Err == nil && ex.RCode == dns.RCodeSuccess {
			if answered == "" {
				answered = fmt.Sprintf("answered by %s in %s", exchangeLabel(ex), roundDur(ex.RTT))
			}
			continue
		}
		what := ex.RCode.String()
		if ex.Err != nil {
			var ne net.Error
			if errors.As(ex.Err, &ne) && ne.Timeout() {
				what = "timeout after " + roundDur(ex.RTT)
			} else {
				what = ex.Err.Error()
			}
		}
		if len(out) < 6 {
			out = append(out, fmt.Sprintf("%s %s %s: %s", exchangeLabel(ex), ex.Name, ex.Type, what))
		}
	}
	if answered != "" {
		out = append([]string{answered}, out...)
	}
	return out
}

func fillDNSError(res *Result, err error, servers []string) {
	res.Status = StatusFail
	res.Error = err.Error()
	var e *dns.Error
	if !errors.As(err, &e) {
		res.Code, res.Summary = "dns.error", err.Error()
		return
	}
	res.Code = "dns." + string(e.Kind)
	res.Summary = err.Error()
	switch e.Kind {
	case dns.ErrNXDomain:
		res.Hint = "the domain does not exist: check the spelling, or whether the domain expired or its delegation is broken"
	case dns.ErrNoData:
		res.Hint = "the name exists but has no A/AAAA record: the DNS zone lacks an address for this host"
	case dns.ErrServFail:
		res.Hint = "the resolver could not complete the lookup: often a DNSSEC validation failure or unreachable authoritative servers; compare with another resolver (-dns 1.1.1.1)"
	case dns.ErrRefused:
		res.Hint = "the resolver refuses to answer you: it may not offer recursion to this network, or the configured DNS server is wrong"
	case dns.ErrTimeout:
		res.Hint = fmt.Sprintf("no DNS server (%s) answered: the resolver is down or UDP/TCP port 53 is blocked", strings.Join(servers, ", "))
	case dns.ErrNetwork:
		res.Hint = "DNS queries could not be sent: no network connectivity or no route to the DNS server"
	case dns.ErrMalformed:
		res.Hint = "DNS answers were garbled: a middlebox may be tampering with DNS traffic"
	}
}

func fillSystemDNSError(res *Result, host string, err error) {
	res.Status = StatusFail
	res.Error = err.Error()
	res.Summary = err.Error()
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsNotFound:
		res.Code = "dns.nxdomain"
		res.Hint = "the system resolver reports that " + host + " does not exist"
	case errors.As(err, &de) && de.IsTimeout:
		res.Code = "dns.timeout"
		res.Hint = "the system resolver timed out"
	default:
		res.Code = "dns.error"
	}
}

// TCP

const maxTCPAttempts = 4

func diagTCP(ctx context.Context, ips []net.IP, t *target, opts *Options) (_ net.Conn, res Result) {
	res = Result{Stage: StageTCP}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	type failure struct {
		addr string
		err  error
		kind tcpKind
	}
	var failures []failure
	for i, ip := range interleave(ips) {
		if i == maxTCPAttempts {
			break
		}
		addr := net.JoinHostPort(ip.String(), t.port)
		d := net.Dialer{Timeout: opts.timeout()}
		attemptStart := time.Now()
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			res.Status = StatusOK
			res.Summary = fmt.Sprintf("connected to %s in %s", addr, roundDur(time.Since(attemptStart)))
			for _, f := range failures {
				res.Details = append(res.Details, fmt.Sprintf("%s failed first: %s", f.addr, f.kind.describe()))
			}
			if len(failures) > 0 {
				res.Status = StatusWarn
				res.Code = "tcp.partial"
				res.Hint = "some addresses of this host are unreachable; clients that try them first will be slow"
			}
			return conn, res
		}
		failures = append(failures, failure{addr, err, classifyTCP(err)})
		res.Details = append(res.Details, fmt.Sprintf("%s: %s after %s", addr, classifyTCP(err).describe(), roundDur(time.Since(attemptStart))))
		if ctx.Err() != nil {
			break
		}
	}

	best := failures[0]
	for _, f := range failures[1:] {
		if f.kind.rank() < best.kind.rank() {
			best = f
		}
	}
	res.Status = StatusFail
	res.Code = "tcp." + string(best.kind)
	res.Error = best.err.Error()
	res.Summary = fmt.Sprintf("cannot connect to %s: %s", best.addr, best.kind.describe())
	res.Hint = best.kind.hint(t.port)
	return nil, res
}

// interleave alternates address families, IPv6 first (RFC 8305).
func interleave(ips []net.IP) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	var out []net.IP
	for i := 0; i < max(len(v4), len(v6)); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out
}

// TLS

func diagTLS(ctx context.Context, raw net.Conn, t *target, opts *Options) (_ net.Conn, res Result) {
	res = Result{Stage: StageTLS}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	sni := t.host
	if opts.ServerName != "" {
		sni = opts.ServerName
	}
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	// Verification is done in a callback so the certificates can be shown
	// even when they are rejected.
	var peer []*x509.Certificate
	verify := func(certs []*x509.Certificate) error {
		peer = certs
		if opts.InsecureSkipVerify || len(certs) == 0 {
			return nil
		}
		vo := x509.VerifyOptions{DNSName: sni, Roots: opts.RootCAs, Intermediates: x509.NewCertPool()}
		for _, c := range certs[1:] {
			vo.Intermediates.AddCert(c)
		}
		_, err := certs[0].Verify(vo)
		return err
	}

	var conn net.Conn
	var info []string
	var err error
	if opts.TLSImpl == "wheel" {
		cfg := &tls13.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				var certs []*x509.Certificate
				for _, der := range rawCerts {
					c, err := x509.ParseCertificate(der)
					if err != nil {
						return err
					}
					certs = append(certs, c)
				}
				return verify(certs)
			},
		}
		c := tls13.Client(raw, cfg)
		if err = c.HandshakeContext(ctx); err == nil {
			st := c.ConnectionState()
			info = append(info, fmt.Sprintf("TLS 1.3 (wheel-cheeze), %s, %v, ALPN %s", tls13.CipherSuiteName(st.CipherSuite), st.CurveID, orNone(st.NegotiatedProtocol)))
			if st.DidHelloRetryRequest {
				info = append(info, "server requested a HelloRetryRequest (different key exchange group)")
			}
			conn = c
		}
	} else {
		cfg := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // diagnose old servers instead of refusing them
			NextProtos:         []string{"http/1.1"},
			VerifyConnection: func(cs tls.ConnectionState) error {
				return verify(cs.PeerCertificates)
			},
		}
		if t.host == sni && net.ParseIP(sni) != nil {
			cfg.ServerName = ""
		}
		c := tls.Client(raw, cfg)
		if err = c.HandshakeContext(ctx); err == nil {
			st := c.ConnectionState()
			info = append(info, fmt.Sprintf("%s, %s, ALPN %s", tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite), orNone(st.NegotiatedProtocol)))
			if st.Version < tls.VersionTLS12 {
				res.Status = StatusWarn
				res.Code = "tls.deprecated_version"
				res.Hint = tls.VersionName(st.Version) + " is deprecated (RFC 8996); modern clients refuse it"
			}
			conn = c
		}
	}

	certInfo, expiring := describeCerts(peer, opts)
	if err != nil {
		fillTLSError(&res, err, sni, peer, opts)
		res.Details = append(res.Details, certInfo...)
		return nil, res
	}
	if res.Status == "" {
		res.Status = StatusOK
	}
	res.Summary = info[0]
	res.Details = append(info[1:], certInfo...)
	if opts.ServerName != "" {
		res.Details = append([]string{"server name (SNI): " + sni}, res.Details...)
	}
	if opts.InsecureSkipVerify {
		res.Details = append(res.Details, "certificate verification was skipped (-insecure)")
	}
	if expiring != "" && res.Status == StatusOK {
		res.Status = StatusWarn
		res.Code = "tls.cert_expiring"
		res.Hint = expiring
	}
	return conn, res
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func describeCerts(certs []*x509.Certificate, opts *Options) (lines []string, expiring string) {
	if len(certs) == 0 {
		return nil, ""
	}
	leaf := certs[0]
	lines = append(lines, "certificate: "+subjectName(leaf))
	if names := certNames(leaf); names != "" {
		lines = append(lines, "valid for: "+names)
	}
	lines = append(lines, "issuer: "+issuerName(leaf))
	left := time.Until(leaf.NotAfter)
	lines = append(lines, fmt.Sprintf("expires: %s (%s)", leaf.NotAfter.UTC().Format("2006-01-02"), daysLeft(left)))
	lines = append(lines, fmt.Sprintf("chain: %d certificate(s) sent by the server", len(certs)))
	warn := opts.ExpiryWarning
	if warn == 0 {
		warn = 14 * 24 * time.Hour
	}
	if left > 0 && left < warn {
		when := "less than a day"
		if days := int(left.Hours() / 24); days > 0 {
			when = fmt.Sprintf("%d days", days)
		}
		expiring = fmt.Sprintf("the certificate expires in %s; renew it soon", when)
	}
	return lines, expiring
}

func daysLeft(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case d < 0:
		return fmt.Sprintf("expired %d days ago", -days)
	case days == 0:
		return "less than a day left"
	}
	return fmt.Sprintf("%d days left", days)
}

func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return "CN=" + c.Subject.CommonName
	}
	return c.Subject.String()
}

func issuerName(c *x509.Certificate) string {
	parts := []string{}
	if c.Issuer.CommonName != "" {
		parts = append(parts, "CN="+c.Issuer.CommonName)
	}
	if len(c.Issuer.Organization) > 0 {
		parts = append(parts, "O="+c.Issuer.Organization[0])
	}
	if len(parts) == 0 {
		return c.Issuer.String()
	}
	return strings.Join(parts, ", ")
}

func certNames(c *x509.Certificate) string {
	var names []string
	names = append(names, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" (+%d more)", len(names)-5)
	}
	return strings.Join(names, ", ")
}

// HTTP

func diagHTTP(ctx context.Context, conn net.Conn, t *target, opts *Options) (res Result) {
	res = Result{Stage: StageHTTP}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}
	deadline := time.Now().Add(opts.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: wheel-netdiag/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		method, t.path, t.hostHeader)
	if _, err := io.WriteString(conn, req); err != nil {
		res.Status, res.Code, res.Error = StatusFail, "http.write_failed", err.Error()
		res.Summary = "could not send the request: " + err.Error()
		return res
	}

	rec := &recorder{r: conn}
	br := bufio.NewReader(rec)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	ttfb := time.Since(start)
	if err != nil {
		res.Status = StatusFail
		res.Error = err.Error()
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			res.Code = "http.timeout"
			res.Summary = fmt.Sprintf("no response within %s", roundDur(opts.timeout()))
			res.Hint = "the server accepted the connection but never answered: it may be overloaded or hung, or the port speaks a different protocol"
		case len(rec.head) == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isReset(err)):
			res.Code = "http.closed"
			res.Summary = "the server closed the connection without responding"
			res.Hint = "the server or a proxy rejected the request silently; check server logs, or whether it expects a different Host or protocol"
		default:
			res.Code = "http.malformed"
			res.Summary = "the response is not valid HTTP/1.x"
			if len(rec.head) > 0 {
				res.Details = append(res.Details, fmt.Sprintf("first bytes: %q", rec.head))
			}
			res.Hint = "the port seems to speak another protocol"
		}
		return res
	}
	defer resp.Body.Close()
	n, bodyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	res.Summary = fmt.Sprintf("%s %s in %s", resp.Proto, resp.Status, roundDur(ttfb))
	if s := resp.Header.Get("Server"); s != "" {
		res.Details = append(res.Details, "server: "+s)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		res.Details = append(res.Details, "content-type: "+ct)
	}
	if method != http.MethodHead {
		body := fmt.Sprintf("body: %d bytes", n)
		if n == 1<<20 {
			body = "body: more than 1 MiB (not read completely)"
		} else if bodyErr != nil {
			body += " (incomplete: " + bodyErr.Error() + ")"
		}
		res.Details = append(res.Details, body)
	}
	code := resp.StatusCode
	switch {
	case code < 300:
		res.Status = StatusOK
	case code < 400:
		res.Status = StatusOK
		if loc := resp.Header.Get("Location"); loc != "" {
			res.Details = append(res.Details, "redirects to "+loc)
		}
	case code < 500:
		res.Status = StatusWarn
		res.Code = "http.client_error"
		res.Hint = map[int]string{
			401: "authentication required",
			403: "access denied: authorization, an IP allow-list or a WAF is blocking the request",
			404: "the path does not exist on this server",
			421: "misdirected request: the server does not serve this host name on this connection",
			429: "rate limited",
		}[code]
		if res.Hint == "" {
			res.Hint = "the server rejected the request"
		}
	default:
		res.Status = StatusFail
		res.Code = "http.server_error"
		res.Hint = map[int]string{
			500: "the application failed while handling the request; check the server logs",
			502: "bad gateway: a proxy or load balancer could not get a valid answer from the upstream server",
			503: "service unavailable: overloaded, in maintenance, or no healthy backends",
			504: "gateway timeout: the upstream server behind a proxy is too slow or unreachable",
		}[code]
		if res.Hint == "" {
			res.Hint = "the server reported an internal error"
		}
	}
	return res
}

// recorder keeps the first bytes read for error reports.
type recorder struct {
	r    io.Reader
	head []byte
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if len(r.head) < 64 {
		r.head = append(r.head, p[:min(n, 64-len(r.head))]...)
	}
	return n, err
}

// QUIC

func diagQUIC(ctx context.Context, ips []net.IP, t *target, opts *Options) (res Result) {
	res = Result{Stage: StageQUIC}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	ip := interleave(ips)[0]
	if opts.Network == "" {
		// Prefer IPv4 for the UDP probe; it is the more common path.
		for _, cand := range ips {
			if cand.To4() != nil {
				ip = cand
				break
			}
		}
	}
	addr := net.JoinHostPort(ip.String(), t.port)
	sni := t.host
	if opts.ServerName != "" {
		sni = opts.ServerName
	}
	var peer []*x509.Certificate
	cfg := &tls13.Config{
		ServerName:         sni,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, der := range rawCerts {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return err
				}
				peer = append(peer, c)
			}
			if opts.InsecureSkipVerify {
				return nil
			}
			vo := x509.VerifyOptions{DNSName: sni, Roots: opts.RootCAs, Intermediates: x509.NewCertPool()}
			for _, c := range peer[1:] {
				vo.Intermediates.AddCert(c)
			}
			_, err := peer[0].Verify(vo)
			return err
		},
	}
	c, err := quic.Dial(ctx, addr, cfg, &quic.Config{HandshakeTimeout: opts.timeout()})
	if err != nil {
		res.Status = StatusFail
		res.Error = err.Error()
		fillQUICError(&res, err, addr, sni, peer, opts)
		return res
	}
	defer c.CloseWithError(0x100, "") // H3_NO_ERROR
	st := c.ConnectionState()
	stats := c.Stats()
	res.Status = StatusOK
	res.Summary = fmt.Sprintf("QUIC v1 handshake with %s in %s, %s, %v, ALPN %s",
		addr, roundDur(time.Since(start)), tls13.CipherSuiteName(st.TLS.CipherSuite), st.TLS.CurveID, st.TLS.NegotiatedProtocol)
	res.Details = append(res.Details, fmt.Sprintf("round-trip time: %s", roundDur(stats.SmoothedRTT)))
	if st.UsedRetry {
		res.Details = append(res.Details, "server validated our address with a Retry packet")
	}
	return res
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return d.Round(time.Microsecond).String()
	case d < time.Second:
		return d.Round(100 * time.Microsecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}
