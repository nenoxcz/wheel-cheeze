package tls13

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"errors"
	"fmt"
	"io"
)

// CurveID identifies a key exchange group (RFC 8446, section 4.2.7).
type CurveID uint16

const (
	CurveP256 CurveID = 0x0017
	CurveP384 CurveID = 0x0018
	CurveP521 CurveID = 0x0019
	X25519    CurveID = 0x001d
	// X25519MLKEM768 is the hybrid post-quantum group combining ML-KEM-768
	// and X25519 (draft-ietf-tls-ecdhe-mlkem).
	X25519MLKEM768 CurveID = 0x11ec
)

func (c CurveID) String() string {
	switch c {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	case X25519:
		return "X25519"
	case X25519MLKEM768:
		return "X25519MLKEM768"
	}
	return fmt.Sprintf("CurveID(%#04x)", uint16(c))
}

// defaultCurvePreferences lists supported groups in preference order. A
// client sends key shares for the first two.
var defaultCurvePreferences = []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}

func supportedGroup(c CurveID) bool {
	switch c {
	case X25519, CurveP256, CurveP384, CurveP521, X25519MLKEM768:
		return true
	}
	return false
}

func ecdhCurve(c CurveID) ecdh.Curve {
	switch c {
	case X25519:
		return ecdh.X25519()
	case CurveP256:
		return ecdh.P256()
	case CurveP384:
		return ecdh.P384()
	case CurveP521:
		return ecdh.P521()
	}
	return nil
}

const (
	mlkemEncapsulationKeySize = mlkem.EncapsulationKeySize768
	mlkemCiphertextSize       = mlkem.CiphertextSize768
	x25519PublicKeySize       = 32
)

// clientKeyShare is the client's ephemeral private state for one group.
type clientKeyShare struct {
	group  CurveID
	ecdh   *ecdh.PrivateKey           // X25519 part for the hybrid group
	mlkem  *mlkem.DecapsulationKey768 // only for X25519MLKEM768
	public []byte                     // KeyShareEntry.key_exchange
}

func generateKeyShare(rand io.Reader, group CurveID) (*clientKeyShare, error) {
	ks := &clientKeyShare{group: group}
	switch group {
	case X25519MLKEM768:
		seed := make([]byte, mlkem.SeedSize)
		if _, err := io.ReadFull(rand, seed); err != nil {
			return nil, err
		}
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, err
		}
		priv, err := ecdh.X25519().GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		ks.mlkem, ks.ecdh = dk, priv
		ks.public = append(dk.EncapsulationKey().Bytes(), priv.PublicKey().Bytes()...)
	default:
		curve := ecdhCurve(group)
		if curve == nil {
			return nil, fmt.Errorf("tls13: unsupported group %v", group)
		}
		priv, err := curve.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		ks.ecdh = priv
		ks.public = priv.PublicKey().Bytes()
	}
	return ks, nil
}

var errBadKeyShare = errors.New("invalid key share")

// sharedSecret completes the exchange with the server's key_exchange value.
func (ks *clientKeyShare) sharedSecret(serverShare []byte) ([]byte, error) {
	if ks.group == X25519MLKEM768 {
		if len(serverShare) != mlkemCiphertextSize+x25519PublicKeySize {
			return nil, errBadKeyShare
		}
		kemSecret, err := ks.mlkem.Decapsulate(serverShare[:mlkemCiphertextSize])
		if err != nil {
			return nil, errBadKeyShare
		}
		ecdhSecret, err := ecdhShared(ks.ecdh, serverShare[mlkemCiphertextSize:])
		if err != nil {
			return nil, err
		}
		return append(kemSecret, ecdhSecret...), nil
	}
	return ecdhShared(ks.ecdh, serverShare)
}

func ecdhShared(priv *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	pub, err := priv.Curve().NewPublicKey(peer)
	if err != nil {
		return nil, errBadKeyShare
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, errBadKeyShare
	}
	return secret, nil
}

// serverKeyExchange answers a client key share, returning the server's
// key_exchange value and the shared secret.
func serverKeyExchange(rand io.Reader, group CurveID, clientShare []byte) (serverShare, secret []byte, err error) {
	if group == X25519MLKEM768 {
		if len(clientShare) != mlkemEncapsulationKeySize+x25519PublicKeySize {
			return nil, nil, errBadKeyShare
		}
		ek, err := mlkem.NewEncapsulationKey768(clientShare[:mlkemEncapsulationKeySize])
		if err != nil {
			return nil, nil, errBadKeyShare
		}
		kemSecret, ciphertext := ek.Encapsulate()
		priv, err := ecdh.X25519().GenerateKey(rand)
		if err != nil {
			return nil, nil, err
		}
		ecdhSecret, err := ecdhShared(priv, clientShare[mlkemEncapsulationKeySize:])
		if err != nil {
			return nil, nil, err
		}
		return append(ciphertext, priv.PublicKey().Bytes()...), append(kemSecret, ecdhSecret...), nil
	}
	curve := ecdhCurve(group)
	if curve == nil {
		return nil, nil, fmt.Errorf("tls13: unsupported group %v", group)
	}
	priv, err := curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	secret, err = ecdhShared(priv, clientShare)
	if err != nil {
		return nil, nil, err
	}
	return priv.PublicKey().Bytes(), secret, nil
}
