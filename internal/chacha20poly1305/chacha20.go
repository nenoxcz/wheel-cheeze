// Package chacha20poly1305 implements the ChaCha20 stream cipher, the
// Poly1305 one-time authenticator and the ChaCha20-Poly1305 AEAD construction
// as specified in RFC 8439.
//
// The Go standard library only ships this construction as an internal
// package, so TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3) and ChaCha20 header
// protection (QUIC) are built on top of this implementation instead.
package chacha20poly1305

import (
	"encoding/binary"
	"math/bits"
)

const (
	// KeySize is the size of a ChaCha20 key in bytes.
	KeySize = 32
	// NonceSize is the size of the IETF ChaCha20 nonce in bytes.
	NonceSize = 12
	// blockSize is the size of one ChaCha20 keystream block.
	blockSize = 64
)

// "expand 32-byte k" as four little-endian words.
const (
	sigma0 = 0x61707865
	sigma1 = 0x3320646e
	sigma2 = 0x79622d32
	sigma3 = 0x6b206574
)

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// block computes one 64-byte ChaCha20 keystream block (RFC 8439, 2.3).
func block(out *[blockSize]byte, key *[8]uint32, counter uint32, nonce *[3]uint32) {
	s := [16]uint32{
		sigma0, sigma1, sigma2, sigma3,
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter, nonce[0], nonce[1], nonce[2],
	}
	x := s
	for i := 0; i < 10; i++ {
		// Column rounds.
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		// Diagonal rounds.
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}
	for i := range x {
		binary.LittleEndian.PutUint32(out[4*i:], x[i]+s[i])
	}
}

// Cipher is a ChaCha20 keystream generator bound to a key, nonce and
// starting block counter.
type Cipher struct {
	key     [8]uint32
	nonce   [3]uint32
	counter uint32
	buf     [blockSize]byte
	bufLen  int // unused keystream bytes left at the end of buf
	// overflow is set once the 32-bit block counter has wrapped; the
	// keystream must not be used past that point.
	overflow bool
}

// NewCipher returns a ChaCha20 cipher for key and nonce whose first
// keystream block uses the given counter.
func NewCipher(key, nonce []byte, counter uint32) *Cipher {
	if len(key) != KeySize {
		panic("chacha20: invalid key size")
	}
	if len(nonce) != NonceSize {
		panic("chacha20: invalid nonce size")
	}
	c := &Cipher{counter: counter}
	for i := range c.key {
		c.key[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	for i := range c.nonce {
		c.nonce[i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	return c
}

// XORKeyStream XORs src with the keystream and writes the result to dst.
// dst and src may overlap exactly.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("chacha20: output smaller than input")
	}
	for len(src) > 0 {
		if c.bufLen == 0 {
			if c.overflow {
				panic("chacha20: counter overflow")
			}
			block(&c.buf, &c.key, c.counter, &c.nonce)
			c.bufLen = blockSize
			c.counter++
			if c.counter == 0 {
				c.overflow = true
			}
		}
		ks := c.buf[blockSize-c.bufLen:]
		n := min(len(src), len(ks))
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ ks[i]
		}
		c.bufLen -= n
		dst, src = dst[n:], src[n:]
	}
}

// KeyStreamBlock returns the raw keystream block for (key, counter, nonce).
// QUIC header protection (RFC 9001, 5.4.4) uses its first five bytes.
func KeyStreamBlock(key []byte, counter uint32, nonce []byte) [blockSize]byte {
	c := NewCipher(key, nonce, counter)
	var out [blockSize]byte
	block(&out, &c.key, c.counter, &c.nonce)
	return out
}
