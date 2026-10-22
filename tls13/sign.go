package tls13

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"slices"
)

// SignatureScheme is a TLS signature algorithm code point (RFC 8446,
// section 4.2.3).
type SignatureScheme uint16

const (
	PKCS1WithSHA256        SignatureScheme = 0x0401
	PKCS1WithSHA384        SignatureScheme = 0x0501
	PKCS1WithSHA512        SignatureScheme = 0x0601
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	PSSWithSHA256          SignatureScheme = 0x0804
	PSSWithSHA384          SignatureScheme = 0x0805
	PSSWithSHA512          SignatureScheme = 0x0806
	Ed25519                SignatureScheme = 0x0807
)

func (s SignatureScheme) String() string {
	switch s {
	case PKCS1WithSHA256:
		return "rsa_pkcs1_sha256"
	case PKCS1WithSHA384:
		return "rsa_pkcs1_sha384"
	case PKCS1WithSHA512:
		return "rsa_pkcs1_sha512"
	case ECDSAWithP256AndSHA256:
		return "ecdsa_secp256r1_sha256"
	case ECDSAWithP384AndSHA384:
		return "ecdsa_secp384r1_sha384"
	case ECDSAWithP521AndSHA512:
		return "ecdsa_secp521r1_sha512"
	case PSSWithSHA256:
		return "rsa_pss_rsae_sha256"
	case PSSWithSHA384:
		return "rsa_pss_rsae_sha384"
	case PSSWithSHA512:
		return "rsa_pss_rsae_sha512"
	case Ed25519:
		return "ed25519"
	}
	return fmt.Sprintf("SignatureScheme(%#04x)", uint16(s))
}

// supportedSignatureAlgorithms is advertised in signature_algorithms. The
// PKCS #1 v1.5 schemes are only acceptable in certificate signatures, which
// are checked by crypto/x509, never in CertificateVerify.
var supportedSignatureAlgorithms = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	PSSWithSHA256,
	Ed25519,
	ECDSAWithP384AndSHA384,
	PSSWithSHA384,
	PSSWithSHA512,
	ECDSAWithP521AndSHA512,
	PKCS1WithSHA256,
	PKCS1WithSHA384,
	PKCS1WithSHA512,
}

func schemeHash(s SignatureScheme) crypto.Hash {
	switch s {
	case ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256:
		return crypto.SHA256
	case ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384:
		return crypto.SHA384
	case ECDSAWithP521AndSHA512, PSSWithSHA512, PKCS1WithSHA512:
		return crypto.SHA512
	}
	return 0 // Ed25519 signs the message directly
}

// schemesForKey returns the CertificateVerify schemes usable with pub, in
// preference order.
func schemesForKey(pub crypto.PublicKey) []SignatureScheme {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return []SignatureScheme{ECDSAWithP256AndSHA256}
		case elliptic.P384():
			return []SignatureScheme{ECDSAWithP384AndSHA384}
		case elliptic.P521():
			return []SignatureScheme{ECDSAWithP521AndSHA512}
		}
	case *rsa.PublicKey:
		// PSS with hash length salt needs emLen >= 2*hLen + 2.
		size := k.Size()
		var out []SignatureScheme
		for _, s := range []SignatureScheme{PSSWithSHA256, PSSWithSHA384, PSSWithSHA512} {
			if size >= 2*schemeHash(s).Size()+2 {
				out = append(out, s)
			}
		}
		return out
	case ed25519.PublicKey:
		return []SignatureScheme{Ed25519}
	}
	return nil
}

// selectSignatureScheme picks the first scheme usable with pub that the peer
// advertised.
func selectSignatureScheme(pub crypto.PublicKey, peer []SignatureScheme) (SignatureScheme, error) {
	for _, s := range schemesForKey(pub) {
		if slices.Contains(peer, s) {
			return s, nil
		}
	}
	return 0, errors.New("no mutually supported signature scheme for the certificate key")
}

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify"
	clientSignatureContext = "TLS 1.3, client CertificateVerify"
)

// signedMessage builds the CertificateVerify input (RFC 8446, 4.4.3).
func signedMessage(context string, transcriptHash []byte) []byte {
	m := make([]byte, 0, 64+len(context)+1+len(transcriptHash))
	for i := 0; i < 64; i++ {
		m = append(m, 0x20)
	}
	m = append(m, context...)
	m = append(m, 0)
	return append(m, transcriptHash...)
}

func signHandshake(rand io.Reader, key crypto.Signer, scheme SignatureScheme, msg []byte) ([]byte, error) {
	if scheme == Ed25519 {
		return key.Sign(rand, msg, crypto.Hash(0))
	}
	h := schemeHash(scheme)
	hh := h.New()
	hh.Write(msg)
	digest := hh.Sum(nil)
	var opts crypto.SignerOpts = h
	if _, ok := key.Public().(*rsa.PublicKey); ok {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	return key.Sign(rand, digest, opts)
}

func verifyHandshake(pub crypto.PublicKey, scheme SignatureScheme, msg, sig []byte) error {
	if !slices.Contains(schemesForKey(pub), scheme) {
		return fmt.Errorf("signature scheme %v does not match the certificate key", scheme)
	}
	if scheme == Ed25519 {
		if !ed25519.Verify(pub.(ed25519.PublicKey), msg, sig) {
			return errors.New("invalid Ed25519 signature")
		}
		return nil
	}
	h := schemeHash(scheme)
	hh := h.New()
	hh.Write(msg)
	digest := hh.Sum(nil)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("invalid ECDSA signature")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return fmt.Errorf("invalid RSA-PSS signature: %w", err)
		}
	default:
		return errors.New("unsupported public key type")
	}
	return nil
}
