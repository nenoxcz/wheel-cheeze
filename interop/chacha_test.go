package interop

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"testing"

	xchacha "golang.org/x/crypto/chacha20poly1305"

	ours "github.com/nenoxcz/wheel-cheeze/internal/chacha20poly1305"
)

// TestChaCha20Poly1305Differential compares the from-scratch AEAD with
// golang.org/x/crypto on random inputs of many sizes.
func TestChaCha20Poly1305Differential(t *testing.T) {
	rnd := mrand.New(mrand.NewSource(1))
	for i := 0; i < 3000; i++ {
		key := make([]byte, 32)
		nonce := make([]byte, 12)
		rand.Read(key)
		rand.Read(nonce)
		pt := make([]byte, rnd.Intn(3000))
		ad := make([]byte, rnd.Intn(64))
		rand.Read(pt)
		rand.Read(ad)

		a, _ := ours.New(key)
		b, _ := xchacha.New(key)
		got := a.Seal(nil, nonce, pt, ad)
		want := b.Seal(nil, nonce, pt, ad)
		if !bytes.Equal(got, want) {
			t.Fatalf("seal mismatch for len(pt)=%d len(ad)=%d", len(pt), len(ad))
		}
		opened, err := a.Open(nil, nonce, want, ad)
		if err != nil || !bytes.Equal(opened, pt) {
			t.Fatalf("open failed: %v", err)
		}
	}
}
