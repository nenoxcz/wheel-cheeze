package quic

// Frame types (RFC 9000, section 19).
const (
	frameTypePadding            = 0x00
	frameTypePing               = 0x01
	frameTypeAck                = 0x02
	frameTypeAckECN             = 0x03
	frameTypeResetStream        = 0x04
	frameTypeStopSending        = 0x05
	frameTypeCrypto             = 0x06
	frameTypeNewToken           = 0x07
	frameTypeStream             = 0x08 // 0x08-0x0f
	frameTypeMaxData            = 0x10
	frameTypeMaxStreamData      = 0x11
	frameTypeMaxStreamsBidi     = 0x12
	frameTypeMaxStreamsUni      = 0x13
	frameTypeDataBlocked        = 0x14
	frameTypeStreamDataBlocked  = 0x15
	frameTypeStreamsBlockedBidi = 0x16
	frameTypeStreamsBlockedUni  = 0x17
	frameTypeNewConnectionID    = 0x18
	frameTypeRetireConnectionID = 0x19
	frameTypePathChallenge      = 0x1a
	frameTypePathResponse       = 0x1b
	frameTypeConnectionClose    = 0x1c
	frameTypeConnectionCloseApp = 0x1d
	frameTypeHandshakeDone      = 0x1e

	streamFlagFin = 0x01
	streamFlagLen = 0x02
	streamFlagOff = 0x04
)

type ackFrame struct {
	// ranges are in descending order; ranges[0].end-1 is the largest
	// acknowledged packet number.
	ranges   []span
	ackDelay uint64 // raw value, before scaling by the ack delay exponent
}

func (f *ackFrame) largest() uint64 { return f.ranges[0].end - 1 }

type cryptoFrame struct {
	offset uint64
	data   []byte
}

type streamFrame struct {
	id     uint64
	offset uint64
	data   []byte
	fin    bool
}

type resetStreamFrame struct {
	id, code, finalSize uint64
}

type stopSendingFrame struct {
	id, code uint64
}

type maxDataFrame struct{ max uint64 }

type maxStreamDataFrame struct{ id, max uint64 }

type maxStreamsFrame struct {
	bidi bool
	max  uint64
}

type newConnectionIDFrame struct {
	seq, retirePriorTo uint64
	cid                []byte
	resetToken         [16]byte
}

type retireConnectionIDFrame struct{ seq uint64 }

type pathChallengeFrame struct{ data [8]byte }

type pathResponseFrame struct{ data [8]byte }

type connectionCloseFrame struct {
	app       bool
	code      uint64
	frameType uint64
	reason    string
}

type (
	paddingFrame       struct{}
	pingFrame          struct{}
	handshakeDoneFrame struct{}
	newTokenFrame      struct{ token []byte }
	// blockedFrame covers DATA_BLOCKED, STREAM_DATA_BLOCKED and
	// STREAMS_BLOCKED, which are informational only.
	blockedFrame struct{}
)

// frameParser reads frames from a decrypted packet payload.
type frameParser struct {
	b   []byte
	err *TransportError
}

func (p *frameParser) varint() uint64 {
	if p.err != nil {
		return 0
	}
	v, n := readVarint(p.b)
	if n == 0 {
		p.fail()
		return 0
	}
	p.b = p.b[n:]
	return v
}

func (p *frameParser) bytes(n uint64) []byte {
	if p.err != nil {
		return nil
	}
	if uint64(len(p.b)) < n {
		p.fail()
		return nil
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v
}

func (p *frameParser) fail() {
	if p.err == nil {
		p.err = transportErr(FrameEncodingError, "truncated or malformed frame")
	}
}

// next parses one frame. It returns the frame type as well, for error
// reporting and for the per-packet-type permission checks.
func (p *frameParser) next() (typ uint64, frame any, err *TransportError) {
	typ = p.varint()
	if p.err != nil {
		return 0, nil, p.err
	}
	switch {
	case typ == frameTypePadding:
		// Collapse runs of padding into one frame.
		for len(p.b) > 0 && p.b[0] == 0 {
			p.b = p.b[1:]
		}
		frame = paddingFrame{}
	case typ == frameTypePing:
		frame = pingFrame{}
	case typ == frameTypeAck || typ == frameTypeAckECN:
		frame = p.parseAck(typ == frameTypeAckECN)
	case typ == frameTypeResetStream:
		frame = resetStreamFrame{id: p.varint(), code: p.varint(), finalSize: p.varint()}
	case typ == frameTypeStopSending:
		frame = stopSendingFrame{id: p.varint(), code: p.varint()}
	case typ == frameTypeCrypto:
		off := p.varint()
		n := p.varint()
		data := p.bytes(n)
		if p.err == nil && off+n > maxVarint {
			p.err = transportErr(FrameEncodingError, "CRYPTO frame beyond 2^62")
		}
		frame = cryptoFrame{offset: off, data: data}
	case typ == frameTypeNewToken:
		tok := p.bytes(p.varint())
		if p.err == nil && len(tok) == 0 {
			p.err = transportErr(FrameEncodingError, "empty NEW_TOKEN")
		}
		frame = newTokenFrame{token: tok}
	case typ >= frameTypeStream && typ <= frameTypeStream|0x07:
		f := streamFrame{id: p.varint(), fin: typ&streamFlagFin != 0}
		if typ&streamFlagOff != 0 {
			f.offset = p.varint()
		}
		if typ&streamFlagLen != 0 {
			f.data = p.bytes(p.varint())
		} else if p.err == nil {
			f.data = p.b
			p.b = nil
		}
		if p.err == nil && f.offset+uint64(len(f.data)) > maxVarint {
			p.err = transportErr(FrameEncodingError, "STREAM frame beyond 2^62")
		}
		frame = f
	case typ == frameTypeMaxData:
		frame = maxDataFrame{max: p.varint()}
	case typ == frameTypeMaxStreamData:
		frame = maxStreamDataFrame{id: p.varint(), max: p.varint()}
	case typ == frameTypeMaxStreamsBidi || typ == frameTypeMaxStreamsUni:
		f := maxStreamsFrame{bidi: typ == frameTypeMaxStreamsBidi, max: p.varint()}
		if p.err == nil && f.max > 1<<60 {
			p.err = transportErr(FrameEncodingError, "MAX_STREAMS above 2^60")
		}
		frame = f
	case typ == frameTypeDataBlocked:
		p.varint()
		frame = blockedFrame{}
	case typ == frameTypeStreamDataBlocked:
		p.varint()
		p.varint()
		frame = blockedFrame{}
	case typ == frameTypeStreamsBlockedBidi || typ == frameTypeStreamsBlockedUni:
		if v := p.varint(); p.err == nil && v > 1<<60 {
			p.err = transportErr(FrameEncodingError, "STREAMS_BLOCKED above 2^60")
		}
		frame = blockedFrame{}
	case typ == frameTypeNewConnectionID:
		f := newConnectionIDFrame{seq: p.varint(), retirePriorTo: p.varint()}
		var l []byte
		if l = p.bytes(1); p.err == nil {
			f.cid = p.bytes(uint64(l[0]))
			copy(f.resetToken[:], p.bytes(16))
		}
		if p.err == nil && (len(f.cid) < 1 || len(f.cid) > 20 || f.retirePriorTo > f.seq) {
			p.err = transportErr(FrameEncodingError, "invalid NEW_CONNECTION_ID")
		}
		frame = f
	case typ == frameTypeRetireConnectionID:
		frame = retireConnectionIDFrame{seq: p.varint()}
	case typ == frameTypePathChallenge:
		var f pathChallengeFrame
		copy(f.data[:], p.bytes(8))
		frame = f
	case typ == frameTypePathResponse:
		var f pathResponseFrame
		copy(f.data[:], p.bytes(8))
		frame = f
	case typ == frameTypeConnectionClose || typ == frameTypeConnectionCloseApp:
		f := connectionCloseFrame{app: typ == frameTypeConnectionCloseApp, code: p.varint()}
		if !f.app {
			f.frameType = p.varint()
		}
		f.reason = string(p.bytes(p.varint()))
		frame = f
	case typ == frameTypeHandshakeDone:
		frame = handshakeDoneFrame{}
	default:
		return typ, nil, &TransportError{Code: FrameEncodingError, FrameType: typ, Reason: "unknown frame type"}
	}
	if p.err != nil {
		p.err.FrameType = typ
		return typ, nil, p.err
	}
	return typ, frame, nil
}

func (p *frameParser) parseAck(ecn bool) ackFrame {
	largest := p.varint()
	delay := p.varint()
	count := p.varint()
	first := p.varint()
	if p.err != nil {
		return ackFrame{}
	}
	if first > largest {
		p.err = transportErr(FrameEncodingError, "ACK range below zero")
		return ackFrame{}
	}
	f := ackFrame{ackDelay: delay}
	smallest := largest - first
	f.ranges = append(f.ranges, span{smallest, largest + 1})
	if count > 1000 {
		p.err = transportErr(FrameEncodingError, "too many ACK ranges")
		return ackFrame{}
	}
	for i := uint64(0); i < count; i++ {
		gap := p.varint()
		length := p.varint()
		if p.err != nil {
			return ackFrame{}
		}
		// The next range ends gap+2 below the previous smallest.
		if smallest < gap+2 {
			p.err = transportErr(FrameEncodingError, "ACK range below zero")
			return ackFrame{}
		}
		end := smallest - gap - 2 // largest in this range
		if length > end {
			p.err = transportErr(FrameEncodingError, "ACK range below zero")
			return ackFrame{}
		}
		smallest = end - length
		f.ranges = append(f.ranges, span{smallest, end + 1})
	}
	if ecn {
		p.varint()
		p.varint()
		p.varint()
	}
	return f
}

// isAckEliciting reports whether a frame type requires an acknowledgment.
func isAckEliciting(typ uint64) bool {
	switch typ {
	case frameTypePadding, frameTypeAck, frameTypeAckECN, frameTypeConnectionClose, frameTypeConnectionCloseApp:
		return false
	}
	return true
}

// allowedInLongHeader reports whether a frame may appear in Initial and
// Handshake packets (RFC 9000, table 3).
func allowedInLongHeader(typ uint64) bool {
	switch typ {
	case frameTypePadding, frameTypePing, frameTypeAck, frameTypeAckECN, frameTypeCrypto, frameTypeConnectionClose:
		return true
	}
	return false
}

// Frame serialization.

func appendAckFrame(b []byte, ranges rangeSet, ackDelay uint64) []byte {
	// ranges is ascending; ACK frames list them descending.
	n := len(ranges)
	largest := ranges[n-1]
	b = appendVarint(b, frameTypeAck)
	b = appendVarint(b, largest.end-1)
	b = appendVarint(b, ackDelay)
	b = appendVarint(b, uint64(n-1))
	b = appendVarint(b, largest.size()-1)
	prevSmallest := largest.start
	for i := n - 2; i >= 0; i-- {
		r := ranges[i]
		b = appendVarint(b, prevSmallest-r.end-1) // gap
		b = appendVarint(b, r.size()-1)
		prevSmallest = r.start
	}
	return b
}

func appendCryptoFrameHeader(b []byte, offset uint64, n int) []byte {
	b = appendVarint(b, frameTypeCrypto)
	b = appendVarint(b, offset)
	return appendVarint(b, uint64(n))
}

func cryptoFrameOverhead(offset uint64, n int) int {
	return 1 + varintLen(offset) + varintLen(uint64(n))
}

func appendStreamFrameHeader(b []byte, id, offset uint64, n int, fin bool) []byte {
	typ := uint64(frameTypeStream | streamFlagLen)
	if offset > 0 {
		typ |= streamFlagOff
	}
	if fin {
		typ |= streamFlagFin
	}
	b = appendVarint(b, typ)
	b = appendVarint(b, id)
	if offset > 0 {
		b = appendVarint(b, offset)
	}
	return appendVarint(b, uint64(n))
}

func streamFrameOverhead(id, offset uint64, n int) int {
	o := 1 + varintLen(id) + varintLen(uint64(n))
	if offset > 0 {
		o += varintLen(offset)
	}
	return o
}

func appendConnectionClose(b []byte, f *connectionCloseFrame) []byte {
	if f.app {
		b = appendVarint(b, frameTypeConnectionCloseApp)
		b = appendVarint(b, f.code)
	} else {
		b = appendVarint(b, frameTypeConnectionClose)
		b = appendVarint(b, f.code)
		b = appendVarint(b, f.frameType)
	}
	reason := f.reason
	if len(reason) > 256 {
		reason = reason[:256]
	}
	b = appendVarint(b, uint64(len(reason)))
	return append(b, reason...)
}
