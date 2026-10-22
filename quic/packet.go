package quic

import (
	"encoding/binary"
	"errors"
)

const version1 uint32 = 0x00000001

// Long header packet types for QUIC v1 (RFC 9000, section 17.2).
const (
	packetTypeInitial   = 0x0
	packetType0RTT      = 0x1
	packetTypeHandshake = 0x2
	packetTypeRetry     = 0x3
)

const (
	maxCIDLen = 20
	// cidLen is the length of the connection IDs this implementation
	// chooses for itself.
	cidLen = 8
	// minInitialDatagram is the minimum size of a datagram carrying an
	// ack-eliciting Initial packet.
	minInitialDatagram = 1200
)

var errMalformedHeader = errors.New("quic: malformed packet header")

// longHeader is a parsed long header, before header protection is removed.
type longHeader struct {
	typ      byte
	version  uint32
	dcid     []byte
	scid     []byte
	token    []byte // Initial: token; Retry: retry token
	pnOffset int    // offset of the packet number field
	end      int    // length of this packet within the datagram
	// Version Negotiation packets.
	versions []uint32
	// Retry packets.
	retryTag []byte
}

// parseLongHeader parses the long header at the start of b. For packets
// carrying a Length field, end marks where the next coalesced packet begins.
func parseLongHeader(b []byte) (*longHeader, error) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return nil, errMalformedHeader
	}
	h := &longHeader{version: binary.BigEndian.Uint32(b[1:5])}
	p := 5
	readCID := func() ([]byte, bool) {
		if p >= len(b) {
			return nil, false
		}
		l := int(b[p])
		p++
		if l > maxCIDLen && h.version == version1 {
			return nil, false
		}
		if p+l > len(b) {
			return nil, false
		}
		cid := b[p : p+l]
		p += l
		return cid, true
	}
	var ok bool
	if h.dcid, ok = readCID(); !ok {
		return nil, errMalformedHeader
	}
	if h.scid, ok = readCID(); !ok {
		return nil, errMalformedHeader
	}

	if h.version == 0 {
		// Version Negotiation.
		rest := b[p:]
		if len(rest) == 0 || len(rest)%4 != 0 {
			return nil, errMalformedHeader
		}
		for i := 0; i < len(rest); i += 4 {
			h.versions = append(h.versions, binary.BigEndian.Uint32(rest[i:]))
		}
		h.end = len(b)
		return h, nil
	}
	if h.version != version1 {
		h.end = len(b)
		return h, nil // caller decides (Version Negotiation on servers)
	}
	if b[0]&0x40 == 0 {
		return nil, errMalformedHeader // fixed bit must be set
	}
	h.typ = (b[0] >> 4) & 0x03
	if h.typ == packetTypeRetry {
		if len(b)-p < 16 {
			return nil, errMalformedHeader
		}
		h.token = b[p : len(b)-16]
		h.retryTag = b[len(b)-16:]
		h.end = len(b)
		return h, nil
	}
	if h.typ == packetTypeInitial {
		l, n := readVarint(b[p:])
		if n == 0 || uint64(len(b)-p-n) < l {
			return nil, errMalformedHeader
		}
		p += n
		h.token = b[p : p+int(l)]
		p += int(l)
	}
	length, n := readVarint(b[p:])
	if n == 0 {
		return nil, errMalformedHeader
	}
	p += n
	if uint64(len(b)-p) < length {
		return nil, errMalformedHeader
	}
	h.pnOffset = p
	h.end = p + int(length)
	return h, nil
}

// peekDCID returns the Destination Connection ID of a packet for routing.
// Short header packets are assumed to use connection IDs of cidLen bytes.
func peekDCID(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	if b[0]&0x80 == 0 {
		if len(b) < 1+cidLen {
			return nil, false
		}
		return b[1 : 1+cidLen], true
	}
	if len(b) < 6 {
		return nil, false
	}
	l := int(b[5])
	if len(b) < 6+l {
		return nil, false
	}
	return b[6 : 6+l], true
}

// appendLongHeader writes a long header up to (excluding) the Length field.
func appendLongHeader(b []byte, typ byte, dcid, scid, token []byte, pnLen int) []byte {
	b = append(b, 0xc0|typ<<4|byte(pnLen-1))
	b = binary.BigEndian.AppendUint32(b, version1)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	if typ == packetTypeInitial {
		b = appendVarint(b, uint64(len(token)))
		b = append(b, token...)
	}
	return b
}

func appendPacketNumber(b []byte, pn uint64, pnLen int) []byte {
	for i := pnLen - 1; i >= 0; i-- {
		b = append(b, byte(pn>>(8*i)))
	}
	return b
}

// buildVersionNegotiation answers a packet of an unsupported version.
func buildVersionNegotiation(clientDCID, clientSCID []byte, randomByte byte) []byte {
	b := []byte{0x80 | randomByte&0x7f, 0, 0, 0, 0}
	b = append(b, byte(len(clientSCID)))
	b = append(b, clientSCID...)
	b = append(b, byte(len(clientDCID)))
	b = append(b, clientDCID...)
	b = binary.BigEndian.AppendUint32(b, version1)
	return b
}

// buildRetry creates a Retry packet (RFC 9000, 17.2.5).
func buildRetry(clientSCID, newSCID, odcid, token []byte, randomByte byte) []byte {
	b := []byte{0xc0 | packetTypeRetry<<4 | randomByte&0x0f}
	b = binary.BigEndian.AppendUint32(b, version1)
	b = append(b, byte(len(clientSCID)))
	b = append(b, clientSCID...)
	b = append(b, byte(len(newSCID)))
	b = append(b, newSCID...)
	b = append(b, token...)
	return append(b, retryIntegrityTag(odcid, b)...)
}
