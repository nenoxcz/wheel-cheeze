package tls13

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"
)

// Certificate is a certificate chain together with the private key of its
// leaf.
type Certificate struct {
	// Certificate holds the DER-encoded chain, leaf first.
	Certificate [][]byte
	PrivateKey  crypto.Signer
	// Leaf is the parsed leaf certificate. It is filled in lazily if nil.
	Leaf *x509.Certificate
}

func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	if len(c.Certificate) == 0 {
		return nil, errors.New("tls13: empty certificate chain")
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// LoadX509KeyPair reads a PEM certificate chain and private key from files.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEM, keyPEM)
}

// X509KeyPair parses a PEM certificate chain and a PEM private key (PKCS #8,
// SEC 1 EC or PKCS #1 RSA).
func X509KeyPair(certPEM, keyPEM []byte) (Certificate, error) {
	var cert Certificate
	for {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return Certificate{}, errors.New("tls13: no CERTIFICATE block found")
	}
	var key any
	for {
		var block *pem.Block
		block, keyPEM = pem.Decode(keyPEM)
		if block == nil {
			return Certificate{}, errors.New("tls13: no private key block found")
		}
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return Certificate{}, fmt.Errorf("tls13: parsing private key: %w", err)
		}
		break
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return Certificate{}, errors.New("tls13: private key is not a crypto.Signer")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return Certificate{}, fmt.Errorf("tls13: parsing leaf certificate: %w", err)
	}
	if !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return Certificate{}, errors.New("tls13: private key does not match the certificate")
	}
	cert.PrivateKey = signer
	cert.Leaf = leaf
	return cert, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equaler)
	return ok && ea.Equal(b)
}

// ClientAuthType controls how a server requests client certificates.
type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// Config configures a TLS 1.3 client or server. A Config may be shared by
// many connections and must not be modified after first use.
type Config struct {
	// Rand provides entropy. Defaults to crypto/rand.Reader.
	Rand io.Reader
	// Time returns the current time for certificate validation.
	Time func() time.Time

	// ServerName is sent in the server_name extension and used to verify
	// the server certificate (client only).
	ServerName string
	// RootCAs is the trust anchor set for server certificates. If nil the
	// system pool is used.
	RootCAs *x509.CertPool
	// InsecureSkipVerify disables server certificate verification. The
	// CertificateVerify signature is still checked.
	InsecureSkipVerify bool
	// VerifyPeerCertificate, if set, is called after normal verification
	// (or instead of it when verification is skipped).
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// Certificates holds the server certificates, or the client certificate
	// used when the server requests one.
	Certificates []Certificate
	// GetCertificate selects a server certificate based on the SNI value.
	// It takes precedence over Certificates.
	GetCertificate func(serverName string) (*Certificate, error)

	// ClientAuth and ClientCAs control client certificate authentication.
	ClientAuth ClientAuthType
	ClientCAs  *x509.CertPool

	// NextProtos lists ALPN protocols in preference order.
	NextProtos []string
	// CipherSuites lists TLS 1.3 cipher suites in preference order.
	CipherSuites []uint16
	// CurvePreferences lists key exchange groups in preference order. A
	// client sends key shares for the first two entries.
	CurvePreferences []CurveID

	// KeyLogWriter receives secrets in NSS key log format, which lets tools
	// such as Wireshark decrypt the traffic. For debugging only.
	KeyLogWriter io.Writer
}

// Clone returns a shallow copy of c.
func (c *Config) Clone() *Config {
	if c == nil {
		return &Config{}
	}
	cc := *c
	return &cc
}

func (c *Config) rand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Config) now() time.Time {
	if c.Time != nil {
		return c.Time()
	}
	return time.Now()
}

func (c *Config) cipherSuites() []uint16 {
	if len(c.CipherSuites) == 0 {
		return defaultCipherSuites
	}
	var out []uint16
	for _, id := range c.CipherSuites {
		if CipherSuiteByID(id) != nil && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func (c *Config) curvePreferences() []CurveID {
	if len(c.CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	var out []CurveID
	for _, g := range c.CurvePreferences {
		if supportedGroup(g) && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

var keyLogMu sync.Mutex

const (
	keyLogClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
	keyLogExporter        = "EXPORTER_SECRET"
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) {
	if c.KeyLogWriter == nil {
		return
	}
	line := fmt.Sprintf("%s %x %x\n", label, clientRandom, secret)
	keyLogMu.Lock()
	defer keyLogMu.Unlock()
	io.WriteString(c.KeyLogWriter, line)
}

// ConnectionState describes a negotiated connection.
type ConnectionState struct {
	Version              uint16
	HandshakeComplete    bool
	CipherSuite          uint16
	CurveID              CurveID
	SignatureScheme      SignatureScheme // scheme of the peer's CertificateVerify
	NegotiatedProtocol   string
	ServerName           string
	DidHelloRetryRequest bool
	PeerCertificates     []*x509.Certificate
	VerifiedChains       [][]*x509.Certificate
}
