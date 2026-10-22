package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var errOpen = errors.New("chacha20poly1305: message authentication failed")

type aead struct {
	key [KeySize]byte
}

// New returns the ChaCha20-Poly1305 AEAD (RFC 8439, 2.8) for a 32-byte key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	a := &aead{}
	copy(a.key[:], key)
	return a, nil
}

func (a *aead) NonceSize() int { return NonceSize }
func (a *aead) Overhead() int  { return TagSize }

// macKey derives the one-time Poly1305 key from keystream block 0.
func (a *aead) macKey(nonce []byte) *poly1305 {
	blk := KeyStreamBlock(a.key[:], 0, nonce)
	var otk [32]byte
	copy(otk[:], blk[:32])
	return newPoly1305(&otk)
}

var zeros [TagSize]byte

func authenticate(p *poly1305, additionalData, ciphertext []byte) [TagSize]byte {
	p.Write(additionalData)
	if r := len(additionalData) % TagSize; r != 0 {
		p.Write(zeros[:TagSize-r])
	}
	p.Write(ciphertext)
	if r := len(ciphertext) % TagSize; r != 0 {
		p.Write(zeros[:TagSize-r])
	}
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(additionalData)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(ciphertext)))
	p.Write(lens[:])
	return p.Sum()
}

// sliceForAppend extends in by n bytes, returning the whole slice and the
// newly appended tail.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length")
	}
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext := out[:len(plaintext)]
	NewCipher(a.key[:], nonce, 1).XORKeyStream(ciphertext, plaintext)
	tag := authenticate(a.macKey(nonce), additionalData, ciphertext)
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length")
	}
	if len(ciphertext) < TagSize {
		return nil, errOpen
	}
	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]
	want := authenticate(a.macKey(nonce), additionalData, ciphertext)
	if subtle.ConstantTimeCompare(want[:], tag) != 1 {
		return nil, errOpen
	}
	ret, out := sliceForAppend(dst, len(ciphertext))
	NewCipher(a.key[:], nonce, 1).XORKeyStream(out, ciphertext)
	return ret, nil
}
