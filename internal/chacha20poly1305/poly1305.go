package chacha20poly1305

import (
	"encoding/binary"
	"math/bits"
)

// TagSize is the size of a Poly1305 authenticator.
const TagSize = 16

// The accumulator h is kept in three 64-bit limbs (h2 holds only a few bits)
// and the clamped key r in two. p = 2^130 - 5.
const (
	rMask0 = 0x0FFFFFFC0FFFFFFF
	rMask1 = 0x0FFFFFFC0FFFFFFC

	p0 = 0xFFFFFFFFFFFFFFFB
	p1 = 0xFFFFFFFFFFFFFFFF
	p2 = 0x0000000000000003
)

// poly1305 is an incremental Poly1305 MAC (RFC 8439, 2.5). A key must only
// ever be used for a single message.
type poly1305 struct {
	h0, h1, h2 uint64
	r0, r1     uint64
	s0, s1     uint64
	buf        [TagSize]byte
	bufLen     int
}

func newPoly1305(key *[32]byte) *poly1305 {
	return &poly1305{
		r0: binary.LittleEndian.Uint64(key[0:8]) & rMask0,
		r1: binary.LittleEndian.Uint64(key[8:16]) & rMask1,
		s0: binary.LittleEndian.Uint64(key[16:24]),
		s1: binary.LittleEndian.Uint64(key[24:32]),
	}
}

func (p *poly1305) Write(msg []byte) {
	if p.bufLen > 0 {
		n := copy(p.buf[p.bufLen:], msg)
		p.bufLen += n
		msg = msg[n:]
		if p.bufLen < TagSize {
			return
		}
		p.blocks(p.buf[:], true)
		p.bufLen = 0
	}
	if full := len(msg) - len(msg)%TagSize; full > 0 {
		p.blocks(msg[:full], true)
		msg = msg[full:]
	}
	p.bufLen = copy(p.buf[:], msg)
}

// blocks absorbs complete 16-byte blocks. For the final partial block the
// caller pads it with 0x01 and zeros itself and passes full=false, so the
// implicit 2^128 bit is not added.
func (p *poly1305) blocks(msg []byte, full bool) {
	h0, h1, h2 := p.h0, p.h1, p.h2
	r0, r1 := p.r0, p.r1
	var hibit uint64
	if full {
		hibit = 1
	}
	for len(msg) >= TagSize {
		// h += m (+ 2^128 for a full block).
		var c uint64
		h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(msg[0:8]), 0)
		h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(msg[8:16]), c)
		h2 += c + hibit
		msg = msg[TagSize:]

		// h *= r. h2 is at most 7 and the top four bits of r0 and r1 are
		// clamped to zero, so the h2 products and the column sums below never
		// overflow their 128-bit accumulators.
		h0r0hi, h0r0lo := bits.Mul64(h0, r0)
		h1r0hi, h1r0lo := bits.Mul64(h1, r0)
		_, h2r0lo := bits.Mul64(h2, r0)
		h0r1hi, h0r1lo := bits.Mul64(h0, r1)
		h1r1hi, h1r1lo := bits.Mul64(h1, r1)
		_, h2r1lo := bits.Mul64(h2, r1)

		// Column sums as 128-bit values (m1 = h1r0 + h0r1, m2 = h2r0 + h1r1).
		m1lo, c := bits.Add64(h1r0lo, h0r1lo, 0)
		m1hi := h1r0hi + h0r1hi + c
		m2lo, c := bits.Add64(h2r0lo, h1r1lo, 0)
		m2hi := h1r1hi + c
		m3lo := h2r1lo

		// Carry-propagate into 64-bit limbs t0..t3.
		t0 := h0r0lo
		t1, c := bits.Add64(m1lo, h0r0hi, 0)
		t2, c := bits.Add64(m2lo, m1hi, c)
		t3, _ := bits.Add64(m3lo, m2hi, c)

		// Partial reduction using 2^130 = 5 (mod p): split at bit 130 and
		// add the high part times 5 (as 4*x + x) back into the low part.
		h0, h1, h2 = t0, t1, t2&3
		cclo, cchi := t2&^3, t3
		h0, c = bits.Add64(h0, cclo, 0)
		h1, c = bits.Add64(h1, cchi, c)
		h2 += c
		cclo, cchi = cclo>>2|cchi<<62, cchi>>2
		h0, c = bits.Add64(h0, cclo, 0)
		h1, c = bits.Add64(h1, cchi, c)
		h2 += c
	}
	p.h0, p.h1, p.h2 = h0, h1, h2
}

// Sum finalizes the MAC and returns the tag.
func (p *poly1305) Sum() [TagSize]byte {
	if p.bufLen > 0 {
		var last [TagSize]byte
		copy(last[:], p.buf[:p.bufLen])
		last[p.bufLen] = 1
		p.blocks(last[:], false)
		p.bufLen = 0
	}

	// Final reduction: h is < 2p here, so subtract p once if h >= p, in
	// constant time.
	t0, b := bits.Sub64(p.h0, p0, 0)
	t1, b := bits.Sub64(p.h1, p1, b)
	_, b = bits.Sub64(p.h2, p2, b)
	// b == 1 means h < p and h must be kept.
	keep := -b // all ones if b == 1
	h0 := p.h0&keep | t0&^keep
	h1 := p.h1&keep | t1&^keep

	// tag = (h + s) mod 2^128
	h0, c := bits.Add64(h0, p.s0, 0)
	h1, _ = bits.Add64(h1, p.s1, c)

	var tag [TagSize]byte
	binary.LittleEndian.PutUint64(tag[0:8], h0)
	binary.LittleEndian.PutUint64(tag[8:16], h1)
	return tag
}
