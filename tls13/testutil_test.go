package tls13

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// testPKI is a CA plus leaf certificates for several key types.
type testPKI struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	pool   *x509.CertPool
}

var (
	pkiOnce sync.Once
	pki     *testPKI
	leafMu  sync.Mutex
	leaves  = map[string]Certificate{}
)

func getPKI(t testing.TB) *testPKI {
	pkiOnce.Do(func() {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "wheel-cheeze test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		ca, _ := x509.ParseCertificate(der)
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		pki = &testPKI{caCert: ca, caKey: key, pool: pool}
	})
	return pki
}

func newKey(t testing.TB, kind string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	switch kind {
	case "p256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// issue creates a leaf certificate signed by the test CA.
func issue(t testing.TB, kind string, notBefore, notAfter time.Time, hosts ...string) Certificate {
	t.Helper()
	p := getPKI(t)
	key := newKey(t, kind)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, key.Public(), p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return Certificate{Certificate: [][]byte{der, p.caCert.Raw}, PrivateKey: key, Leaf: leaf}
}

// leafCert returns a cached valid certificate for "example.test" and
// 127.0.0.1 with the given key type.
func leafCert(t testing.TB, kind string) Certificate {
	leafMu.Lock()
	defer leafMu.Unlock()
	if c, ok := leaves[kind]; ok {
		return c
	}
	c := issue(t, kind, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "example.test", "127.0.0.1")
	leaves[kind] = c
	return c
}

func toStdCert(c Certificate) tls.Certificate {
	return tls.Certificate{Certificate: c.Certificate, PrivateKey: c.PrivateKey, Leaf: c.Leaf}
}

// pipe returns a connected pair of TCP connections on loopback. Real
// sockets (unlike net.Pipe) buffer writes, as the TLS flights require.
func pipe(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-ch
	if b == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
