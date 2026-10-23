// Command netdiag finds out at which layer a request fails:
// DNS -> TCP -> TLS -> HTTP (and optionally QUIC).
//
//	netdiag https://example.com/
//	netdiag -dns 1.1.1.1 -quic example.com
//	netdiag -json http://10.0.0.5:8080/health
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nenoxcz/wheel-cheeze/netdiag"
)

// Exit codes identify the failing stage for scripts.
var exitCodes = map[netdiag.Stage]int{
	netdiag.StageDNS:  2,
	netdiag.StageTCP:  3,
	netdiag.StageTLS:  4,
	netdiag.StageHTTP: 5,
}

func main() {
	var opts netdiag.Options
	var (
		jsonOut  = flag.Bool("json", false, "print the report as JSON")
		noColor  = flag.Bool("no-color", false, "disable colors")
		caFile   = flag.String("cacert", "", "PEM file with CA certificates to trust instead of the system roots")
		ipv4     = flag.Bool("4", false, "use IPv4 addresses only")
		ipv6     = flag.Bool("6", false, "use IPv6 addresses only")
		deadline = flag.Duration("deadline", 0, "overall time limit (default: none)")
	)
	flag.DurationVar(&opts.Timeout, "timeout", 5*time.Second, "time limit per stage")
	flag.StringVar(&opts.DNSServer, "dns", "", "query this DNS server instead of /etc/resolv.conf;\n\t\taccepts ip[:port], tls://ip#name (DoT), https://host/dns-query (DoH), quic://host (DoQ)")
	flag.BoolVar(&opts.SystemResolver, "system-resolver", false, "use the operating system resolver instead of querying DNS directly")
	flag.StringVar(&opts.TLSImpl, "tls", "stdlib", "TLS client: stdlib (crypto/tls, TLS 1.0-1.3) or wheel (this repository's TLS 1.3)")
	flag.BoolVar(&opts.InsecureSkipVerify, "insecure", false, "report certificate problems without failing the TLS stage")
	flag.StringVar(&opts.ServerName, "sni", "", "server name for SNI and certificate verification (default: the URL host)")
	flag.StringVar(&opts.Method, "method", "GET", "HTTP method")
	flag.BoolVar(&opts.QUIC, "quic", false, "also probe QUIC/HTTP3 over UDP (HTTPS targets)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: netdiag [flags] URL\n\n")
		fmt.Fprintf(os.Stderr, "Checks DNS -> TCP -> TLS -> HTTP and reports which stage fails and why.\n")
		fmt.Fprintf(os.Stderr, "Exit status: 0 ok, 2 DNS, 3 TCP, 4 TLS, 5 HTTP, 1 usage error.\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	if *ipv4 && *ipv6 {
		fatal("-4 and -6 are mutually exclusive")
	}
	if *ipv4 {
		opts.Network = "ip4"
	} else if *ipv6 {
		opts.Network = "ip6"
	}
	if opts.TLSImpl != "stdlib" && opts.TLSImpl != "wheel" {
		fatal("-tls must be stdlib or wheel")
	}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fatal(err.Error())
		}
		opts.RootCAs = x509.NewCertPool()
		if !opts.RootCAs.AppendCertsFromPEM(pem) {
			fatal("no certificates found in " + *caFile)
		}
	}

	ctx := context.Background()
	if *deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *deadline)
		defer cancel()
	}
	report, err := netdiag.Run(ctx, flag.Arg(0), opts)
	if err != nil {
		fatal(err.Error())
	}
	if *jsonOut {
		report.WriteJSON(os.Stdout)
	} else {
		report.WriteText(os.Stdout, useColor() && !*noColor)
	}
	if !report.OK {
		os.Exit(exitCodes[report.FailedStage])
	}
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "netdiag:", msg)
	os.Exit(1)
}
