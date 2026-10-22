package netdiag

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/nenoxcz/wheel-cheeze/quic"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// tcpKind classifies a failed connect.
type tcpKind string

const (
	tcpRefused         tcpKind = "refused"
	tcpReset           tcpKind = "reset"
	tcpTimeout         tcpKind = "timeout"
	tcpHostUnreachable tcpKind = "host_unreachable"
	tcpNetUnreachable  tcpKind = "net_unreachable"
	tcpBlocked         tcpKind = "blocked_locally"
	tcpOther           tcpKind = "error"
)

func classifyTCP(err error) tcpKind {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return tcpRefused
	case errors.Is(err, syscall.ECONNRESET):
		return tcpReset
	case errors.Is(err, syscall.EHOSTUNREACH):
		return tcpHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL):
		return tcpNetUnreachable
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return tcpBlocked
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return tcpTimeout
	}
	return tcpOther
}

// rank orders kinds by how much they tell about the target: a refusal
// proves the host is reachable, a missing route says little.
func (k tcpKind) rank() int {
	switch k {
	case tcpRefused:
		return 0
	case tcpReset:
		return 1
	case tcpTimeout:
		return 2
	case tcpHostUnreachable:
		return 3
	case tcpBlocked:
		return 4
	case tcpNetUnreachable:
		return 5
	}
	return 6
}

func (k tcpKind) describe() string {
	switch k {
	case tcpRefused:
		return "connection refused"
	case tcpReset:
		return "connection reset"
	case tcpTimeout:
		return "connection timed out"
	case tcpHostUnreachable:
		return "host unreachable"
	case tcpNetUnreachable:
		return "network unreachable"
	case tcpBlocked:
		return "blocked by local policy"
	}
	return "connect failed"
}

func (k tcpKind) hint(port string) string {
	switch k {
	case tcpRefused:
		return fmt.Sprintf("the host is reachable but nothing accepts connections on port %s (service down or wrong port), or a firewall actively rejects them", port)
	case tcpReset:
		return "the connection was reset during setup: a firewall or load balancer is rejecting it"
	case tcpTimeout:
		return "no answer to the TCP SYN: a firewall is silently dropping packets, the host is down, or the address is wrong"
	case tcpHostUnreachable:
		return "a router reports the host as unreachable: it is offline or the route ends before it"
	case tcpNetUnreachable:
		return "this machine has no route to that network (for IPv6 addresses: probably no IPv6 connectivity; try -4)"
	case tcpBlocked:
		return "the local firewall or security policy forbids the connection"
	}
	return ""
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// Alert descriptions as crypto/tls words them, mapped to RFC names.
var stdlibAlerts = map[string]tls13.Alert{
	"close notify":                    tls13.AlertCloseNotify,
	"unexpected message":              tls13.AlertUnexpectedMessage,
	"bad record MAC":                  tls13.AlertBadRecordMAC,
	"handshake failure":               tls13.AlertHandshakeFailure,
	"bad certificate":                 tls13.AlertBadCertificate,
	"unsupported certificate":         tls13.AlertUnsupportedCertificate,
	"revoked certificate":             tls13.AlertCertificateRevoked,
	"expired certificate":             tls13.AlertCertificateExpired,
	"unknown certificate":             tls13.AlertCertificateUnknown,
	"illegal parameter":               tls13.AlertIllegalParameter,
	"unknown certificate authority":   tls13.AlertUnknownCA,
	"access denied":                   tls13.AlertAccessDenied,
	"error decoding message":          tls13.AlertDecodeError,
	"error decrypting message":        tls13.AlertDecryptError,
	"protocol version not supported":  tls13.AlertProtocolVersion,
	"insufficient security level":     tls13.AlertInsufficientSecurity,
	"internal error":                  tls13.AlertInternalError,
	"inappropriate fallback":          tls13.AlertInappropriateFallback,
	"missing extension":               tls13.AlertMissingExtension,
	"unsupported extension":           tls13.AlertUnsupportedExtension,
	"unrecognized name":               tls13.AlertUnrecognizedName,
	"certificate required":            tls13.AlertCertificateRequired,
	"no application protocol":         tls13.AlertNoApplicationProtocol,
	"bad certificate status response": tls13.AlertBadCertificateStatusResponse,
}

// remoteAlert extracts an alert sent by the server.
func remoteAlert(err error) (tls13.Alert, bool) {
	var ae *tls13.AlertError
	if errors.As(err, &ae) && ae.Remote {
		return ae.Alert, true
	}
	msg := err.Error()
	if i := strings.Index(msg, "remote error: tls: "); i >= 0 {
		if a, ok := stdlibAlerts[msg[i+len("remote error: tls: "):]]; ok {
			return a, true
		}
	}
	return 0, false
}

func alertHint(a tls13.Alert, impl string) string {
	switch a {
	case tls13.AlertHandshakeFailure:
		return "no common cipher suite or key exchange group, or the server requires SNI or a client certificate"
	case tls13.AlertProtocolVersion:
		if impl == "wheel" {
			return "the server does not support TLS 1.3, the only version the wheel-cheeze client speaks; retry with -tls stdlib"
		}
		return "the server does not accept any TLS version this client offers"
	case tls13.AlertUnrecognizedName:
		return "the server does not host this name (SNI); check the host name or -sni"
	case tls13.AlertCertificateRequired, tls13.AlertBadCertificate:
		return "the server requires a client certificate (mutual TLS)"
	case tls13.AlertAccessDenied:
		return "the server denies access to this client"
	case tls13.AlertInternalError:
		return "the server hit an internal TLS error"
	case tls13.AlertNoApplicationProtocol:
		return "the server does not support the requested application protocol (ALPN)"
	}
	return "the server aborted the handshake"
}

// fillTLSError classifies a failed TLS handshake.
func fillTLSError(res *Result, err error, sni string, certs []*x509.Certificate, opts *Options) {
	res.Status = StatusFail
	res.Error = err.Error()
	code, summary, hint := classifyTLS(err, sni, certs, opts)
	res.Code, res.Summary, res.Hint = "tls."+code, summary, hint
}

func classifyTLS(err error, sni string, certs []*x509.Certificate, opts *Options) (code, summary, hint string) {
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	var wheelHdr *tls13.RecordHeaderError
	var stdHdr tls.RecordHeaderError
	var ne net.Error

	header := func(h []byte) (string, string, string) {
		if strings.HasPrefix(string(h), "HTTP/") {
			return "not_tls", "the server answered in plaintext HTTP, not TLS",
				"this port does not speak TLS: use http:// or the HTTPS port"
		}
		return "not_tls", fmt.Sprintf("the server's reply is not TLS (first bytes %q)", h),
			"another protocol is listening on this port"
	}

	switch {
	case errors.As(err, &hostErr):
		names := certNames(hostErr.Certificate)
		if names == "" {
			names = subjectName(hostErr.Certificate)
		}
		return "cert_hostname", fmt.Sprintf("the certificate is not valid for %s", sni),
			"it covers " + names + ": wrong host name, missing SAN, or a proxy/CDN serving the wrong certificate"
	case errors.As(err, &authErr):
		if len(certs) == 1 && certs[0].Issuer.String() == certs[0].Subject.String() {
			return "cert_untrusted", "the server uses a self-signed certificate",
				"trust it explicitly with -cacert, or install a certificate from a public CA"
		}
		issuer := "an unknown authority"
		if authErr.Cert != nil {
			issuer = issuerName(authErr.Cert)
		}
		return "cert_untrusted", "the certificate is issued by " + issuer + ", which is not trusted",
			"the server may be missing an intermediate certificate, use a private CA (-cacert), or a proxy/antivirus is intercepting TLS"
	case errors.As(err, &invalidErr):
		c := invalidErr.Cert
		switch invalidErr.Reason {
		case x509.Expired:
			now := time.Now()
			if c != nil && now.Before(c.NotBefore) {
				return "cert_not_yet_valid", fmt.Sprintf("the certificate is not valid before %s", c.NotBefore.UTC().Format(time.RFC3339)),
					"check this machine's clock, or the server installed a certificate too early"
			}
			if c != nil {
				return "cert_expired", fmt.Sprintf("the certificate expired on %s (%s)", c.NotAfter.UTC().Format("2006-01-02"), daysLeft(time.Until(c.NotAfter))),
					"the server must renew its certificate (or this machine's clock is wrong)"
			}
			return "cert_expired", "the certificate has expired", "the server must renew its certificate"
		}
		return "cert_invalid", "the certificate chain is invalid: " + invalidErr.Error(), "the server's certificate chain is misconfigured"
	case errors.As(err, &wheelHdr):
		return header(wheelHdr.Header[:])
	case errors.As(err, &stdHdr):
		return header(stdHdr.RecordHeader[:])
	}
	if a, ok := remoteAlert(err); ok {
		return "alert_" + a.String(), "the server rejected the handshake with alert " + a.String(), alertHint(a, opts.TLSImpl)
	}
	var ae *tls13.AlertError
	if errors.As(err, &ae) {
		return "protocol_error", "the server sent an invalid handshake: " + err.Error(), "the server's TLS implementation misbehaves, or a middlebox modified the handshake"
	}
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), isReset(err),
		strings.Contains(err.Error(), "closed by peer"):
		return "closed", "the server closed the connection during the handshake",
			"often a firewall or DPI blocking this SNI, or the server rejects the offered TLS versions/ciphers without an alert"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, os.ErrDeadlineExceeded), strings.Contains(err.Error(), "deadline exceeded"):
		return "timeout", fmt.Sprintf("no handshake response within %s", roundDur(opts.timeout())),
			"the server does not speak TLS on this port, or a middlebox is dropping the handshake"
	}
	return "error", "handshake failed: " + err.Error(), ""
}

func fillQUICError(res *Result, err error, addr, sni string, certs []*x509.Certificate, opts *Options) {
	var te *quic.TransportError
	var ae *quic.ApplicationError
	var vne *quic.VersionNegotiationError
	switch {
	case errors.Is(err, quic.ErrHandshakeTimeout):
		res.Code = "quic.timeout"
		res.Summary = fmt.Sprintf("no QUIC response from %s within %s", addr, roundDur(opts.timeout()))
		res.Hint = "UDP port " + portOf(addr) + " is blocked somewhere on the path, or the server does not offer HTTP/3"
	case errors.As(err, &vne):
		res.Code = "quic.version"
		res.Summary = fmt.Sprintf("the server does not support QUIC v1 (offers %#x)", vne.Offered)
	case errors.As(err, &te) && te.TLSError != nil:
		code, summary, hint := classifyTLS(te.TLSError, sni, certs, opts)
		res.Code, res.Summary, res.Hint = "quic.tls_"+code, summary, hint
	case errors.As(err, &te) && te.Remote && te.Code.IsCryptoError():
		a := tls13.Alert(te.Code - 0x100)
		if a == tls13.AlertNoApplicationProtocol {
			res.Code = "quic.no_h3"
			res.Summary = "the server speaks QUIC but not HTTP/3 (ALPN h3)"
			return
		}
		res.Code = "quic.tls_alert_" + a.String()
		res.Summary = "the server rejected the TLS handshake with alert " + a.String()
		res.Hint = alertHint(a, "wheel")
	case errors.As(err, &te):
		res.Code = "quic.closed"
		res.Summary = "the connection was closed: " + te.Code.String()
		if te.Reason != "" {
			res.Summary += " (" + te.Reason + ")"
		}
	case errors.As(err, &ae):
		res.Code = "quic.closed"
		res.Summary = err.Error()
	default:
		res.Code = "quic.error"
		res.Summary = err.Error()
	}
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}
