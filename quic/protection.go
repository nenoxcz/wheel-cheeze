package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/nenoxcz/wheel-cheeze/internal/chacha20poly1305"
	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// Packet protection (RFC 9001, section 5).

var initialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// Retry integrity protection for QUIC v1 (RFC 9001, section 5.8).
var (
	retryKeyV1   = []byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e}
	retryNonceV1 = []byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}
)

const aeadTagLen = 16

// headerProtector computes the five-byte header protection mask from a
// 16-byte ciphertext sample.
type headerProtector interface {
	mask(sample []byte) [5]byte
}

type aesHeaderProtector struct{ block cipher.Block }

func (h aesHeaderProtector) mask(sample []byte) [5]byte {
	var out [16]byte
	h.block.Encrypt(out[:], sample)
	var m [5]byte
	copy(m[:], out[:5])
	return m
}

type chachaHeaderProtector struct{ key []byte }

func (h chachaHeaderProtector) mask(sample []byte) [5]byte {
	counter := binary.LittleEndian.Uint32(sample[:4])
	ks := chacha20poly1305.KeyStreamBlock(h.key, counter, sample[4:16])
	var m [5]byte
	copy(m[:], ks[:5])
	return m
}

// packetKeys protects packets in one direction at one encryption level.
type packetKeys struct {
	suite  *tls13.CipherSuite
	secret []byte
	aead   cipher.AEAD
	iv     []byte
	hp     headerProtector
}

func newHeaderProtector(suite *tls13.CipherSuite, secret []byte) headerProtector {
	key := suite.ExpandLabel(secret, "quic hp", nil, suite.KeyLen)
	if suite.IsChaCha20() {
		return chachaHeaderProtector{key}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("quic: header protection key: " + err.Error())
	}
	return aesHeaderProtector{block}
}

// newPacketKeys derives keys from a TLS traffic secret. hp may be passed to
// reuse the header protection key across a key update.
func newPacketKeys(suite *tls13.CipherSuite, secret []byte, hp headerProtector) *packetKeys {
	key := suite.ExpandLabel(secret, "quic key", nil, suite.KeyLen)
	iv := suite.ExpandLabel(secret, "quic iv", nil, 12)
	aead, err := suite.NewAEAD(key)
	if err != nil {
		panic("quic: packet protection key: " + err.Error())
	}
	if hp == nil {
		hp = newHeaderProtector(suite, secret)
	}
	return &packetKeys{suite: suite, secret: secret, aead: aead, iv: iv, hp: hp}
}

// next derives the keys for the following key phase (RFC 9001, 6.1). The
// header protection key does not change.
func (k *packetKeys) next() *packetKeys {
	h := k.suite.Hash.Size()
	return newPacketKeys(k.suite, k.suite.ExpandLabel(k.secret, "quic ku", nil, h), k.hp)
}

func (k *packetKeys) nonce(pn uint64) []byte {
	n := make([]byte, len(k.iv))
	copy(n, k.iv)
	for i := 0; i < 8; i++ {
		n[len(n)-1-i] ^= byte(pn >> (8 * i))
	}
	return n
}

// initialSecrets derives the client and server Initial secrets from the
// client's first Destination Connection ID.
func initialSecrets(dcid []byte) (client, server []byte) {
	suite := tls13.CipherSuiteByID(tls13.TLS_AES_128_GCM_SHA256)
	initial, err := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	if err != nil {
		panic(err)
	}
	client = suite.ExpandLabel(initial, "client in", nil, 32)
	server = suite.ExpandLabel(initial, "server in", nil, 32)
	return client, server
}

// initialKeys returns the (write, read) keys for the Initial space.
func initialKeys(dcid []byte, isClient bool) (seal, open *packetKeys) {
	suite := tls13.CipherSuiteByID(tls13.TLS_AES_128_GCM_SHA256)
	c, s := initialSecrets(dcid)
	ck, sk := newPacketKeys(suite, c, nil), newPacketKeys(suite, s, nil)
	if isClient {
		return ck, sk
	}
	return sk, ck
}

// retryIntegrityTag computes the Retry Integrity Tag over the Retry pseudo
// packet.
func retryIntegrityTag(odcid, retryWithoutTag []byte) []byte {
	block, _ := aes.NewCipher(retryKeyV1)
	aead, _ := cipher.NewGCM(block)
	pseudo := make([]byte, 0, 1+len(odcid)+len(retryWithoutTag))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, retryWithoutTag...)
	return aead.Seal(nil, retryNonceV1, nil, pseudo)
}

var errDecrypt = errors.New("quic: packet decryption failed")

// headerMask returns the first-byte mask bits for long or short headers.
func headerMask(long bool) byte {
	if long {
		return 0x0f
	}
	return 0x1f
}

// removeHeaderProtection unmasks the first byte and packet number of pkt in
// place and returns the truncated packet number and its length.
func removeHeaderProtection(pkt []byte, pnOffset int, hp headerProtector) (truncated uint64, pnLen int, err error) {
	if len(pkt) < pnOffset+4+16 {
		return 0, 0, errors.New("quic: packet too short for header protection sample")
	}
	mask := hp.mask(pkt[pnOffset+4 : pnOffset+20])
	long := pkt[0]&0x80 != 0
	pkt[0] ^= mask[0] & headerMask(long)
	pnLen = int(pkt[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
		truncated = truncated<<8 | uint64(pkt[pnOffset+i])
	}
	return truncated, pnLen, nil
}

// decryptPayload opens the packet payload in place. header is everything up
// to and including the packet number.
func decryptPayload(keys *packetKeys, pn uint64, header, ciphertext []byte) ([]byte, error) {
	plain, err := keys.aead.Open(ciphertext[:0], keys.nonce(pn), ciphertext, header)
	if err != nil {
		return nil, errDecrypt
	}
	return plain, nil
}

// sealPacket encrypts payload after header (which ends with the packet
// number) and applies header protection, returning the full packet.
func sealPacket(keys *packetKeys, pn uint64, header []byte, pnOffset, pnLen int, payload []byte) []byte {
	out := make([]byte, len(header), len(header)+len(payload)+aeadTagLen)
	copy(out, header)
	out = keys.aead.Seal(out, keys.nonce(pn), payload, header)
	mask := keys.hp.mask(out[pnOffset+4 : pnOffset+20])
	long := out[0]&0x80 != 0
	out[0] ^= mask[0] & headerMask(long)
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

// pnLength picks the packet number encoding length (RFC 9000, A.2).
func pnLength(pn uint64, largestAcked int64) int {
	var unacked uint64
	if largestAcked < 0 {
		unacked = pn + 1
	} else {
		unacked = pn - uint64(largestAcked)
	}
	switch {
	case unacked < 1<<7:
		return 1
	case unacked < 1<<15:
		return 2
	case unacked < 1<<23:
		return 3
	}
	return 4
}

// decodePacketNumber reconstructs a full packet number (RFC 9000, A.3).
func decodePacketNumber(largest int64, truncated uint64, pnLen int) uint64 {
	expected := uint64(largest + 1)
	win := uint64(1) << (8 * pnLen)
	hwin := win / 2
	mask := win - 1
	candidate := (expected &^ mask) | truncated
	if candidate+hwin <= expected && candidate < (1<<62)-win {
		return candidate + win
	}
	if candidate > expected+hwin && candidate >= win {
		return candidate - win
	}
	return candidate
}
