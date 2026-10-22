package quic

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/nenoxcz/wheel-cheeze/tls13"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9001, appendix A.1.
func TestInitialSecretsRFC9001(t *testing.T) {
	dcid := unhex(t, "8394c8f03e515708")
	c, s := initialSecrets(dcid)
	if want := unhex(t, "c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea"); !bytes.Equal(c, want) {
		t.Fatalf("client_initial_secret = %x", c)
	}
	if want := unhex(t, "3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b"); !bytes.Equal(s, want) {
		t.Fatalf("server_initial_secret = %x", s)
	}
	suite := tls13.CipherSuiteByID(tls13.TLS_AES_128_GCM_SHA256)
	check := func(secret []byte, key, iv, hp string) {
		t.Helper()
		if got := suite.ExpandLabel(secret, "quic key", nil, 16); !bytes.Equal(got, unhex(t, key)) {
			t.Errorf("key = %x", got)
		}
		if got := suite.ExpandLabel(secret, "quic iv", nil, 12); !bytes.Equal(got, unhex(t, iv)) {
			t.Errorf("iv = %x", got)
		}
		if got := suite.ExpandLabel(secret, "quic hp", nil, 16); !bytes.Equal(got, unhex(t, hp)) {
			t.Errorf("hp = %x", got)
		}
	}
	check(c, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2")
	check(s, "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314")
}

// RFC 9001, appendix A.5: ChaCha20-Poly1305 short header packet.
func TestChaCha20ShortHeaderRFC9001(t *testing.T) {
	suite := tls13.CipherSuiteByID(tls13.TLS_CHACHA20_POLY1305_SHA256)
	secret := unhex(t, "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b")
	keys := newPacketKeys(suite, secret, nil)
	if want := unhex(t, "c6d98ff3441c3fe1b2182094f69caa2e d4b716b65488960a7a984979fb23e1c8"); !bytes.Equal(suite.ExpandLabel(secret, "quic key", nil, 32), want) {
		t.Fatalf("key mismatch")
	}
	if want := unhex(t, "e0459b3474bdd0e44a41c144"); !bytes.Equal(keys.iv, want) {
		t.Fatalf("iv = %x", keys.iv)
	}
	if want := unhex(t, "25a282b9e82f06f21f488917a4fc8f1b 73573685608597d0efcb076b0ab7a7a4"); !bytes.Equal(suite.ExpandLabel(secret, "quic hp", nil, 32), want) {
		t.Fatalf("hp key mismatch")
	}
	ku := suite.ExpandLabel(secret, "quic ku", nil, 32)
	if want := unhex(t, "1223504755036d556342ee9361d25342 1a826c9ecdf3c7148684b36b714881f9"); !bytes.Equal(ku, want) {
		t.Fatalf("ku = %x", ku)
	}

	// Packet number 654360564, payload 01 (PING), header 4200bff4.
	pn := uint64(654360564)
	header := unhex(t, "4200bff4")
	pkt := sealPacket(keys, pn, header, 1, 3, []byte{0x01})
	if want := unhex(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"); !bytes.Equal(pkt, want) {
		t.Fatalf("protected packet = %x", pkt)
	}

	// And back.
	truncated, pnLen, err := removeHeaderProtection(pkt, 1, keys.hp)
	if err != nil {
		t.Fatal(err)
	}
	full := decodePacketNumber(654360563, truncated, pnLen)
	if full != pn {
		t.Fatalf("decoded pn %d", full)
	}
	plain, err := decryptPayload(keys, full, pkt[:1+pnLen], pkt[1+pnLen:])
	if err != nil || !bytes.Equal(plain, []byte{0x01}) {
		t.Fatalf("decrypt: %v %x", err, plain)
	}
}

// RFC 9001, appendix A.4: Retry packet.
func TestRetryIntegrityRFC9001(t *testing.T) {
	odcid := unhex(t, "8394c8f03e515708")
	retry := unhex(t, "ff000000010008f067a5502a4262b5746f6b656e")
	tag := retryIntegrityTag(odcid, retry)
	if want := unhex(t, "04a265ba2eff4d829058fb3f0f2496ba"); !bytes.Equal(tag, want) {
		t.Fatalf("retry tag = %x", tag)
	}
}

func TestDecodePacketNumber(t *testing.T) {
	// RFC 9000, A.3 example.
	if got := decodePacketNumber(0xa82f30ea, 0x9b32, 2); got != 0xa82f9b32 {
		t.Fatalf("got %#x", got)
	}
	for _, largest := range []int64{-1, 0, 100, 1 << 20, 1<<32 + 5} {
		for _, delta := range []uint64{1, 2, 50, 127} {
			pn := uint64(largest+1) + delta - 1
			l := pnLength(pn, largest)
			trunc := pn & (1<<(8*l) - 1)
			if got := decodePacketNumber(largest, trunc, l); got != pn {
				t.Fatalf("largest %d pn %d len %d: decoded %d", largest, pn, l, got)
			}
		}
	}
}

func TestAckFrameRoundTrip(t *testing.T) {
	var rs rangeSet
	for _, pn := range []uint64{0, 1, 2, 5, 6, 10, 11, 12, 13, 20} {
		rs.add(pn, pn+1)
	}
	b := appendAckFrame(nil, rs, 7)
	p := frameParser{b: b}
	typ, f, err := p.next()
	if err != nil || typ != frameTypeAck {
		t.Fatalf("parse: %v", err)
	}
	ack := f.(ackFrame)
	if ack.ackDelay != 7 || ack.largest() != 20 {
		t.Fatalf("ack %+v", ack)
	}
	var got rangeSet
	for _, r := range ack.ranges {
		got.add(r.start, r.end)
	}
	if len(got) != len(rs) {
		t.Fatalf("ranges %v want %v", got, rs)
	}
	for i := range got {
		if got[i] != rs[i] {
			t.Fatalf("ranges %v want %v", got, rs)
		}
	}
}

func TestRangeSet(t *testing.T) {
	var s rangeSet
	s.add(10, 20)
	s.add(30, 40)
	s.add(20, 30) // bridges
	if len(s) != 1 || s[0] != (span{10, 40}) {
		t.Fatalf("%v", s)
	}
	s.remove(15, 25)
	if len(s) != 2 || s[0] != (span{10, 15}) || s[1] != (span{25, 40}) {
		t.Fatalf("%v", s)
	}
	if !s.contains(10) || s.contains(15) || !s.containsRange(26, 40) || s.containsRange(14, 26) {
		t.Fatalf("contains wrong for %v", s)
	}
	s.trimBelow(30)
	if len(s) != 1 || s[0] != (span{30, 40}) {
		t.Fatalf("%v", s)
	}
}

func TestTransportParametersRoundTrip(t *testing.T) {
	p := defaultTransportParameters()
	p.originalDestinationCID = []byte{1, 2, 3}
	p.initialSourceCID = []byte{4, 5}
	p.initialMaxData = 1 << 20
	p.maxStreamsBidi = 100
	p.disableActiveMigration = true
	p.statelessResetToken = bytes.Repeat([]byte{7}, 16)
	got, err := parseTransportParameters(p.marshal(true), true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.originalDestinationCID, p.originalDestinationCID) || got.initialMaxData != p.initialMaxData ||
		got.maxStreamsBidi != 100 || !got.disableActiveMigration || !bytes.Equal(got.statelessResetToken, p.statelessResetToken) {
		t.Fatalf("got %+v", got)
	}
	// Server-only parameters from a client are an error.
	if _, err := parseTransportParameters(p.marshal(true), false); err == nil {
		t.Fatalf("accepted original_destination_connection_id from a client")
	}
}
