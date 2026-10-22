package tls13

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	_ "crypto/sha256" // register SHA-256
	_ "crypto/sha512" // register SHA-384
	"hash"

	"github.com/nenoxcz/wheel-cheeze/internal/chacha20poly1305"
)

// TLS 1.3 cipher suites (RFC 8446, appendix B.4).
const (
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
)

// CipherSuite describes a TLS 1.3 cipher suite: an AEAD and the hash used
// by the HKDF key schedule. It is exported so that QUIC packet protection
// can derive its keys from the traffic secrets.
type CipherSuite struct {
	ID     uint16
	Name   string
	Hash   crypto.Hash
	KeyLen int
	aead   func(key []byte) (cipher.AEAD, error)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var cipherSuites = []*CipherSuite{
	{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", crypto.SHA256, 16, newGCM},
	{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", crypto.SHA384, 32, newGCM},
	{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", crypto.SHA256, 32, chacha20poly1305.New},
}

// defaultCipherSuites is the preference order used when Config.CipherSuites
// is empty.
var defaultCipherSuites = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_256_GCM_SHA384,
}

// CipherSuiteByID returns the suite with the given code point, or nil.
func CipherSuiteByID(id uint16) *CipherSuite {
	for _, s := range cipherSuites {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// CipherSuiteName returns the IANA name of a TLS 1.3 cipher suite.
func CipherSuiteName(id uint16) string {
	if s := CipherSuiteByID(id); s != nil {
		return s.Name
	}
	return "unknown"
}

// IsChaCha20 reports whether the suite uses ChaCha20 (which also selects
// ChaCha20-based QUIC header protection).
func (s *CipherSuite) IsChaCha20() bool { return s.ID == TLS_CHACHA20_POLY1305_SHA256 }

// NewAEAD returns the suite's AEAD keyed with key.
func (s *CipherSuite) NewAEAD(key []byte) (cipher.AEAD, error) { return s.aead(key) }

func (s *CipherSuite) newHash() hash.Hash { return s.Hash.New() }

// ExpandLabel implements HKDF-Expand-Label (RFC 8446, section 7.1).
func (s *CipherSuite) ExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	var b builder
	b.u16(uint16(length))
	b.bytes8([]byte("tls13 " + label))
	b.bytes8(context)
	out, err := hkdf.Expand(s.newHash, secret, string(b.buf), length)
	if err != nil {
		// Only possible if length exceeds 255*HashLen, which no caller does.
		panic("tls13: HKDF-Expand-Label: " + err.Error())
	}
	return out
}

// extract implements HKDF-Extract(salt, ikm). A nil ikm means a string of
// HashLen zero bytes, as used throughout the TLS 1.3 key schedule.
func (s *CipherSuite) extract(ikm, salt []byte) []byte {
	if ikm == nil {
		ikm = make([]byte, s.Hash.Size())
	}
	out, err := hkdf.Extract(s.newHash, ikm, salt)
	if err != nil {
		panic("tls13: HKDF-Extract: " + err.Error())
	}
	return out
}

// deriveSecret implements Derive-Secret. A nil transcript hashes the empty
// string.
func (s *CipherSuite) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = s.newHash()
	}
	return s.ExpandLabel(secret, label, transcript.Sum(nil), s.Hash.Size())
}

// TrafficKey derives the record protection key and IV from a traffic secret.
func (s *CipherSuite) TrafficKey(secret []byte) (key, iv []byte) {
	key = s.ExpandLabel(secret, "key", nil, s.KeyLen)
	iv = s.ExpandLabel(secret, "iv", nil, aeadNonceLength)
	return key, iv
}

// NextTrafficSecret derives application_traffic_secret_N+1 (RFC 8446,
// section 7.2).
func (s *CipherSuite) NextTrafficSecret(secret []byte) []byte {
	return s.ExpandLabel(secret, "traffic upd", nil, s.Hash.Size())
}

// finishedMAC computes verify_data for a Finished message.
func (s *CipherSuite) finishedMAC(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := s.ExpandLabel(baseKey, "finished", nil, s.Hash.Size())
	mac := hmac.New(s.newHash, finishedKey)
	mac.Write(transcript.Sum(nil))
	return mac.Sum(nil)
}

// exportKeyingMaterial implements the TLS 1.3 exporter (RFC 8446, 7.5).
func (s *CipherSuite) exportKeyingMaterial(exporterSecret []byte, label string, context []byte, length int) []byte {
	secret := s.deriveSecret(exporterSecret, label, nil)
	h := s.newHash()
	h.Write(context)
	return s.ExpandLabel(secret, "exporter", h.Sum(nil), length)
}

const aeadNonceLength = 12

// keySchedule tracks the TLS 1.3 secrets for one connection (RFC 8446,
// section 7.1). Pre-shared keys are not supported, so the early secret is
// always derived from zeros.
type keySchedule struct {
	suite *CipherSuite

	handshakeSecret []byte
	masterSecret    []byte

	clientHandshakeSecret []byte
	serverHandshakeSecret []byte
	clientAppSecret       []byte
	serverAppSecret       []byte
	exporterSecret        []byte
}

// deriveHandshake derives the handshake traffic secrets from the (EC)DHE
// shared secret. transcript must cover ClientHello...ServerHello.
func (ks *keySchedule) deriveHandshake(sharedSecret []byte, transcript hash.Hash) {
	s := ks.suite
	early := s.extract(nil, nil)
	ks.handshakeSecret = s.extract(sharedSecret, s.deriveSecret(early, "derived", nil))
	ks.clientHandshakeSecret = s.deriveSecret(ks.handshakeSecret, "c hs traffic", transcript)
	ks.serverHandshakeSecret = s.deriveSecret(ks.handshakeSecret, "s hs traffic", transcript)
}

// deriveApplication derives the application traffic and exporter secrets.
// transcript must cover ClientHello...server Finished.
func (ks *keySchedule) deriveApplication(transcript hash.Hash) {
	s := ks.suite
	ks.masterSecret = s.extract(nil, s.deriveSecret(ks.handshakeSecret, "derived", nil))
	ks.clientAppSecret = s.deriveSecret(ks.masterSecret, "c ap traffic", transcript)
	ks.serverAppSecret = s.deriveSecret(ks.masterSecret, "s ap traffic", transcript)
	ks.exporterSecret = s.deriveSecret(ks.masterSecret, "exp master", transcript)
}
