// Package netdiag diagnoses a URL by walking the layers a request
// travels through, DNS -> TCP -> TLS -> HTTP (and optionally QUIC), and
// reports at which stage and why it fails.
package netdiag

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Stage is one layer of the connection.
type Stage string

const (
	StageDNS  Stage = "DNS"
	StageTCP  Stage = "TCP"
	StageTLS  Stage = "TLS"
	StageHTTP Stage = "HTTP"
	StageQUIC Stage = "QUIC"
)

// Status is the outcome of a stage.
type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn" // worked, but something deserves attention
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

// Result describes one stage.
type Result struct {
	Stage      Stage         `json:"stage"`
	Status     Status        `json:"status"`
	Duration   time.Duration `json:"-"`
	DurationMS float64       `json:"duration_ms"`
	// Summary is a one-line description of what happened.
	Summary string `json:"summary"`
	// Details holds supporting facts (addresses, certificate data, ...).
	Details []string `json:"details,omitempty"`
	// Code is a stable machine-readable cause such as "tcp.refused".
	Code string `json:"code,omitempty"`
	// Hint suggests likely causes or next steps.
	Hint string `json:"hint,omitempty"`
	// Error is the underlying error message.
	Error string `json:"error,omitempty"`
}

// Report is the outcome of a diagnosis.
type Report struct {
	Target string   `json:"target"`
	Scheme string   `json:"scheme"`
	Host   string   `json:"host"`
	Port   string   `json:"port"`
	Path   string   `json:"path"`
	Stages []Result `json:"stages"`
	// FailedStage is the first stage of the TCP path that failed.
	FailedStage Stage         `json:"failed_stage,omitempty"`
	OK          bool          `json:"ok"`
	Total       time.Duration `json:"-"`
	TotalMS     float64       `json:"total_ms"`
}

// Stage returns the result for s, or nil.
func (r *Report) Stage(s Stage) *Result {
	for i := range r.Stages {
		if r.Stages[i].Stage == s {
			return &r.Stages[i]
		}
	}
	return nil
}

// Options control a diagnosis. The zero value is usable.
type Options struct {
	// Timeout bounds each stage. Default 5s.
	Timeout time.Duration
	// DNSServer ("ip" or "ip:port") overrides /etc/resolv.conf.
	DNSServer string
	// SystemResolver uses the operating system resolver instead of
	// querying DNS servers directly.
	SystemResolver bool
	// Network restricts addresses to "ip4" or "ip6".
	Network string
	// TLSImpl selects the TLS client: "stdlib" (crypto/tls, TLS 1.0-1.3)
	// or "wheel" (this repository's TLS 1.3 implementation).
	TLSImpl string
	// RootCAs replaces the system trust store.
	RootCAs *x509.CertPool
	// InsecureSkipVerify reports certificate problems without failing.
	InsecureSkipVerify bool
	// ServerName overrides the SNI / verification name.
	ServerName string
	// Method is the HTTP method. Default GET.
	Method string
	// QUIC additionally probes QUIC (UDP) for HTTPS targets.
	QUIC bool
	// ExpiryWarning flags certificates expiring sooner. Default 14 days.
	ExpiryWarning time.Duration
	// HostsFile overrides /etc/hosts for the built-in resolver ("" uses
	// the default; "-" disables it).
	HostsFile string
}

func (o *Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 5 * time.Second
}

type target struct {
	url        *url.URL
	host, port string
	hostHeader string
	path       string
	https      bool
}

// parseTarget accepts "https://host/path", "http://host:8080",
// "host:port" or a bare host name (HTTPS is assumed).
func parseTarget(s string) (*target, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil, errors.New("empty target")
	}
	if !strings.Contains(raw, "://") {
		scheme := "https"
		if h, p, err := net.SplitHostPort(raw); err == nil && h != "" && p == "80" {
			scheme = "http"
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", s, err)
	}
	t := &target{url: u}
	switch u.Scheme {
	case "https":
		t.https, t.port = true, "443"
	case "http":
		t.port = "80"
	default:
		return nil, fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	t.host = u.Hostname()
	if t.host == "" {
		return nil, fmt.Errorf("target %q has no host", s)
	}
	if p := u.Port(); p != "" {
		t.port = p
	}
	t.hostHeader = u.Host
	t.path = u.RequestURI()
	if t.path == "" {
		t.path = "/"
	}
	return t, nil
}

// Run diagnoses target. It only returns an error if the target cannot be
// parsed; network failures are reported in the Report.
func Run(ctx context.Context, targetURL string, opts Options) (*Report, error) {
	t, err := parseTarget(targetURL)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	r := &Report{Target: targetURL, Host: t.host, Port: t.port, Path: t.path, Scheme: t.url.Scheme}
	defer func() {
		r.Total = time.Since(start)
		r.TotalMS = ms(r.Total)
		for i := range r.Stages {
			r.Stages[i].DurationMS = ms(r.Stages[i].Duration)
		}
	}()

	order := []Stage{StageDNS, StageTCP}
	if t.https {
		order = append(order, StageTLS)
	}
	order = append(order, StageHTTP)
	fail := func(s Stage) {
		r.FailedStage = s
		for _, rest := range order {
			if r.Stage(rest) == nil {
				r.Stages = append(r.Stages, Result{Stage: rest, Status: StatusSkipped, Summary: "skipped: " + string(s) + " failed"})
			}
		}
	}

	addrs, res := diagDNS(ctx, t, &opts)
	r.Stages = append(r.Stages, res)
	if res.Status == StatusFail {
		fail(StageDNS)
		return r, nil
	}

	conn, res := diagTCP(ctx, addrs, t, &opts)
	r.Stages = append(r.Stages, res)
	if res.Status == StatusFail {
		fail(StageTCP)
		return r, nil
	}
	defer conn.Close()

	if t.https {
		var tconn net.Conn
		tconn, res = diagTLS(ctx, conn, t, &opts)
		r.Stages = append(r.Stages, res)
		if res.Status == StatusFail {
			fail(StageTLS)
			r.addQUIC(ctx, addrs, t, &opts)
			return r, nil
		}
		conn = tconn
		defer conn.Close()
	}

	res = diagHTTP(ctx, conn, t, &opts)
	r.Stages = append(r.Stages, res)
	if res.Status == StatusFail {
		fail(StageHTTP)
	} else {
		r.OK = true
	}
	r.addQUIC(ctx, addrs, t, &opts)
	return r, nil
}

func (r *Report) addQUIC(ctx context.Context, addrs []net.IP, t *target, opts *Options) {
	if opts.QUIC && t.https {
		r.Stages = append(r.Stages, diagQUIC(ctx, addrs, t, opts))
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
