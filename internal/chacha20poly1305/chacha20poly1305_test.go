package chacha20poly1305

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.NewReplacer(" ", "", "\n", "", "\t", "", ":", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seq(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i)
	}
	return b
}

const sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

// RFC 8439, 2.3.2.
func TestBlockFunction(t *testing.T) {
	got := KeyStreamBlock(seq(0, 32), 1, unhex(t, "000000090000004a00000000"))
	want := unhex(t, `
		10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
		c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
		d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
		b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e`)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("block mismatch:\n got %x\nwant %x", got, want)
	}
}

// RFC 8439, 2.4.2.
func TestEncryption(t *testing.T) {
	want := unhex(t, `
		6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
		e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
		f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
		16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
		07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
		52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
		5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
		87 4d`)
	nonce := unhex(t, "000000000000004a00000000")
	got := make([]byte, len(sunscreen))
	NewCipher(seq(0, 32), nonce, 1).XORKeyStream(got, []byte(sunscreen))
	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext mismatch:\n got %x\nwant %x", got, want)
	}

	// Streaming in odd-sized pieces must produce the same keystream.
	c := NewCipher(seq(0, 32), nonce, 1)
	got2 := []byte(sunscreen)
	for off := 0; off < len(got2); {
		n := min(7, len(got2)-off)
		c.XORKeyStream(got2[off:off+n], got2[off:off+n])
		off += n
	}
	if !bytes.Equal(got2, want) {
		t.Fatalf("streaming ciphertext mismatch")
	}
}

// RFC 8439, 2.5.2.
func TestPoly1305(t *testing.T) {
	var key [32]byte
	copy(key[:], unhex(t, "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"))
	msg := []byte("Cryptographic Forum Research Group")
	want := unhex(t, "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")

	p := newPoly1305(&key)
	p.Write(msg)
	if got := p.Sum(); !bytes.Equal(got[:], want) {
		t.Fatalf("tag mismatch: got %x want %x", got, want)
	}

	// Byte-at-a-time absorption must match.
	p = newPoly1305(&key)
	for i := range msg {
		p.Write(msg[i : i+1])
	}
	if got := p.Sum(); !bytes.Equal(got[:], want) {
		t.Fatalf("incremental tag mismatch: got %x want %x", got, want)
	}
}

// TestPoly1305Reduction compares the limb arithmetic against a math/big
// reference, including all-0xff messages that keep the accumulator close to
// the modulus.
func TestPoly1305Reduction(t *testing.T) {
	for i := 0; i < 2000; i++ {
		var key [32]byte
		rand.Read(key[:])
		n := i % 100
		msg := make([]byte, n)
		if i%3 == 0 {
			for j := range msg {
				msg[j] = 0xff
			}
		} else {
			rand.Read(msg)
		}
		p := newPoly1305(&key)
		p.Write(msg)
		got := p.Sum()
		want := poly1305Reference(&key, msg)
		if got != want {
			t.Fatalf("mismatch for key %x msg %x:\n got %x\nwant %x", key, msg, got, want)
		}
	}
}

// RFC 8439, 2.8.2.
func TestAEAD(t *testing.T) {
	key := seq(0x80, 32)
	nonce := unhex(t, "07000000 4041424344454647")
	aad := unhex(t, "50515253c0c1c2c3c4c5c6c7")
	wantCT := unhex(t, `
		d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
		a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
		3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
		1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
		92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
		fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
		3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
		61 16`)
	wantTag := unhex(t, "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91")

	a, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := a.Seal(nil, nonce, []byte(sunscreen), aad)
	if !bytes.Equal(sealed[:len(sunscreen)], wantCT) {
		t.Fatalf("ciphertext mismatch:\n got %x\nwant %x", sealed[:len(sunscreen)], wantCT)
	}
	if !bytes.Equal(sealed[len(sunscreen):], wantTag) {
		t.Fatalf("tag mismatch: got %x want %x", sealed[len(sunscreen):], wantTag)
	}

	opened, err := a.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != sunscreen {
		t.Fatalf("roundtrip mismatch")
	}

	// In-place operation.
	buf := append([]byte(nil), sunscreen...)
	buf = a.Seal(buf[:0], nonce, buf, aad)
	if !bytes.Equal(buf, sealed) {
		t.Fatalf("in-place seal mismatch")
	}
	buf, err = a.Open(buf[:0], nonce, buf, aad)
	if err != nil || string(buf) != sunscreen {
		t.Fatalf("in-place open failed: %v", err)
	}

	// Any modification must be rejected.
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := a.Open(nil, nonce, bad, aad); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, err := a.Open(nil, nonce, sealed, aad[1:]); err == nil {
		t.Fatalf("tampered AAD accepted")
	}
}

// poly1305Reference is a direct transcription of RFC 8439, 2.5.1.
func poly1305Reference(key *[32]byte, msg []byte) [TagSize]byte {
	le := func(b []byte) *big.Int {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return new(big.Int).SetBytes(r)
	}
	r := le(key[:16])
	r.And(r, le(unhexMust("ffffff0ffcffff0ffcffff0ffcffff0f")))
	s := le(key[16:])
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	acc := new(big.Int)
	for len(msg) > 0 {
		n := min(16, len(msg))
		blk := append(append([]byte(nil), msg[:n]...), 1)
		acc.Add(acc, le(blk))
		acc.Mul(acc, r)
		acc.Mod(acc, p)
		msg = msg[n:]
	}
	acc.Add(acc, s)
	b := acc.Bytes()
	var out [TagSize]byte
	for i := 0; i < TagSize && i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func unhexMust(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
