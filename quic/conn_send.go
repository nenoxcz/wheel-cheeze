package quic

import "time"

// outPacket is a packet being assembled, before protection.
type outPacket struct {
	space        int
	pn           uint64
	pnLen        int
	header       []byte // long: up to the Length field; short: up to the packet number
	payload      []byte
	frames       []sentFrame
	ackEliciting bool
	padded       bool
}

func (p *outPacket) size() int {
	n := len(p.header) + p.pnLen + len(p.payload) + aeadTagLen
	if p.space != spaceApp {
		n += 2 // two-byte Length field
	}
	return n
}

func (c *Conn) packetHeader(space, pnLen int) []byte {
	switch space {
	case spaceInitial:
		var token []byte
		if c.isClient {
			token = c.retryToken
		}
		return appendLongHeader(nil, packetTypeInitial, c.dcid, c.scid, token, pnLen)
	case spaceHandshake:
		return appendLongHeader(nil, packetTypeHandshake, c.dcid, c.scid, nil, pnLen)
	}
	b := []byte{0x40 | byte(pnLen-1)}
	if c.writePhase {
		b[0] |= 0x04
	}
	return append(b, c.dcid...)
}

// buildDatagrams assembles everything that may be sent now. The caller
// holds c.mu.
func (c *Conn) buildDatagrams(now time.Time) [][]byte {
	var out [][]byte
	for len(out) < maxDatagramsPerRound {
		d := c.buildDatagram(now)
		if d == nil {
			break
		}
		out = append(out, d)
	}
	if len(out) == maxDatagramsPerRound {
		c.wake() // there may be more
	}
	return out
}

func (c *Conn) buildDatagram(now time.Time) []byte {
	budget := maxDatagramSize
	if !c.isClient && !c.addressValidated {
		// Anti-amplification limit (RFC 9000, section 8).
		budget = min(budget, 3*c.ampRecv-c.ampSent)
		if budget <= 0 {
			return nil
		}
	}
	var pkts []*outPacket
	size := 0
	for space := 0; space < numSpaces; space++ {
		if space == spaceInitial && budget < minInitialDatagram {
			continue // could not be padded as required
		}
		left := budget - size
		if left < 48 {
			break
		}
		if p := c.buildPacket(space, left, now); p != nil {
			pkts = append(pkts, p)
			size += p.size()
		}
	}
	if c.state == stateClosing && c.closeSendPending {
		c.closeSendPending = false
		if !c.closeSent {
			c.closeSent = true
			close(c.closeSentCh)
		}
	}
	if len(pkts) == 0 {
		return nil
	}

	// Datagrams with Initial packets are padded to 1200 bytes: always for
	// clients, for servers when ack-eliciting (RFC 9000, section 14.1).
	needPad := false
	for _, p := range pkts {
		if p.space == spaceInitial && (c.isClient || p.ackEliciting) {
			needPad = true
		}
	}
	if needPad && size < minInitialDatagram {
		last := pkts[len(pkts)-1]
		pad := minInitialDatagram - size
		last.payload = append(last.payload, make([]byte, pad)...)
		last.padded = true
		size += pad
	}

	dgram := make([]byte, 0, size)
	sentHandshake := false
	for _, p := range pkts {
		dgram = c.seal(dgram, p, now)
		sentHandshake = sentHandshake || p.space == spaceHandshake
	}
	if !c.isClient && !c.addressValidated {
		c.ampSent += len(dgram)
	}
	c.stats.BytesSent += uint64(len(dgram))
	if c.isClient && sentHandshake {
		// RFC 9001, 4.9.1: a client discards Initial keys when it first
		// sends a Handshake packet.
		c.dropSpace(spaceInitial)
	}
	return dgram
}

func (c *Conn) seal(dst []byte, p *outPacket, now time.Time) []byte {
	sp := c.spaces[p.space]
	keys := sp.writeKeys
	if p.space == spaceApp {
		keys = c.appWrite
	}
	hdr := p.header
	if p.space != spaceApp {
		hdr = appendVarint2(hdr, uint64(p.pnLen+len(p.payload)+aeadTagLen))
	}
	pnOffset := len(hdr)
	hdr = appendPacketNumber(hdr, p.pn, p.pnLen)
	pkt := sealPacket(keys, p.pn, hdr, pnOffset, p.pnLen, p.payload)
	sp.nextPN++
	if p.space == spaceApp && c.writePhaseFirstPN < 0 {
		c.writePhaseFirstPN = int64(p.pn)
	}
	c.stats.PacketsSent++
	if c.state == stateOpen {
		sent := &sentPacket{
			pn:           p.pn,
			sentTime:     now,
			size:         len(pkt),
			ackEliciting: p.ackEliciting,
			inFlight:     p.ackEliciting || p.padded,
			frames:       p.frames,
		}
		sp.sent = append(sp.sent, sent)
		c.cc.onSent(sent)
		if p.ackEliciting {
			sp.ackElicitingInFlight++
			sp.lastAckElicitingSent = now
			if !c.ackElicitingSentNow {
				// The idle timer restarts with the first ack-eliciting
				// packet sent after receiving (RFC 9000, 10.1).
				c.ackElicitingSentNow = true
				c.lastActivity = now
			}
		}
	}
	return append(dst, pkt...)
}

func (c *Conn) hasDataFor(space int) bool {
	sp := c.spaces[space]
	if sp.crypto.hasPending() || c.probes[space] > 0 {
		return true
	}
	if space != spaceApp {
		return false
	}
	return c.pingPending || c.handshakeDonePend || c.maxDataPending ||
		c.maxStreamsPending[0] || c.maxStreamsPending[1] ||
		len(c.pendingRetire) > 0 || len(c.pathResponses) > 0 || len(c.sendQueue) > 0
}

// buildPacket assembles one packet for space of at most maxSize bytes, or
// returns nil if there is nothing to send.
func (c *Conn) buildPacket(space, maxSize int, now time.Time) *outPacket {
	sp := c.spaces[space]
	keys := sp.writeKeys
	if space == spaceApp {
		keys = c.appWrite
	}
	if keys == nil || sp.discarded {
		return nil
	}
	pnLen := pnLength(sp.nextPN, sp.largestAcked)
	p := &outPacket{space: space, pn: sp.nextPN, pnLen: pnLen, header: c.packetHeader(space, pnLen)}
	room := maxSize - p.size()
	if room < 24 {
		return nil
	}

	if c.state == stateClosing {
		if !c.closeSendPending {
			return nil
		}
		f := *c.closeFrame
		if space != spaceApp && f.app {
			// Application closes are not visible before 1-RTT (RFC 9000,
			// 10.2.3).
			f = connectionCloseFrame{code: uint64(ApplicationErrorCode)}
		}
		if len(f.reason) > room-24 {
			f.reason = f.reason[:max(room-24, 0)]
		}
		p.payload = appendConnectionClose(nil, &f)
		return p
	}
	if c.state != stateOpen {
		return nil
	}

	probe := c.probes[space] > 0
	cwndOK := probe || c.cc.canSend(maxSize)
	ackDue := sp.ackElicitingUnacked > 0 && !now.Before(sp.ackDeadline)
	var payload []byte
	if sp.ackPending && len(sp.recvd) > 0 && (ackDue || (cwndOK && c.hasDataFor(space))) {
		var delay uint64
		if space == spaceApp {
			delay = uint64(now.Sub(sp.largestRecvdTime).Microseconds()) >> ackDelayExponent
		}
		ranges := sp.recvd
		ack := appendAckFrame(nil, ranges, delay)
		for len(ack) > room && len(ranges) > 1 {
			ranges = ranges[1:] // report only the most recent ranges
			ack = appendAckFrame(nil, ranges, delay)
		}
		payload = ack
		p.frames = append(p.frames, sentFrame{kind: fkAck, id: sp.recvd.max()})
		sp.ackPending = false
		sp.ackElicitingUnacked = 0
		sp.ackDeadline = time.Time{}
	}

	if cwndOK {
		if space == spaceApp {
			payload = c.appendControlFrames(p, payload, room)
		}
		for sp.crypto.hasPending() {
			avail := room - len(payload) - 11 // frame type, offset and length
			if avail <= 0 {
				break
			}
			off, data := sp.crypto.next(avail)
			payload = appendCryptoFrameHeader(payload, off, len(data))
			payload = append(payload, data...)
			p.frames = append(p.frames, sentFrame{kind: fkCrypto, offset: off, length: uint64(len(data))})
			p.ackEliciting = true
		}
		if space == spaceApp {
			payload = c.appendStreamFrames(p, payload, room)
		}
		if (probe || (space == spaceApp && c.pingPending)) && !p.ackEliciting && len(payload) < room {
			payload = append(payload, frameTypePing)
			p.frames = append(p.frames, sentFrame{kind: fkPing})
			p.ackEliciting = true
		}
	}
	if len(payload) == 0 {
		return nil
	}
	if p.ackEliciting {
		if c.probes[space] > 0 {
			c.probes[space]--
		}
		if space == spaceApp {
			c.pingPending = false
		}
	}
	// The header protection sample needs four bytes after the start of
	// the packet number (RFC 9001, 5.4.2).
	if n := p.pnLen + len(payload); n < 4 {
		payload = append(payload, make([]byte, 4-n)...)
	}
	p.payload = payload
	return p
}

func (c *Conn) appendControlFrames(p *outPacket, payload []byte, room int) []byte {
	fits := func(n int) bool { return len(payload)+n <= room }
	add := func(kind frameKind, id uint64) {
		p.frames = append(p.frames, sentFrame{kind: kind, id: id})
		p.ackEliciting = true
	}
	if c.handshakeDonePend && fits(1) {
		payload = append(payload, frameTypeHandshakeDone)
		add(fkHandshakeDone, 0)
		c.handshakeDonePend = false
	}
	if c.maxDataPending && fits(9) {
		payload = appendVarint(payload, frameTypeMaxData)
		payload = appendVarint(payload, c.recvMaxData)
		add(fkMaxData, 0)
		c.maxDataPending = false
	}
	for k, kind := range []frameKind{fkMaxStreamsBidi, fkMaxStreamsUni} {
		if c.maxStreamsPending[k] && fits(9) {
			payload = appendVarint(payload, uint64(frameTypeMaxStreamsBidi+k))
			payload = appendVarint(payload, c.maxPeerStreams[k])
			add(kind, 0)
			c.maxStreamsPending[k] = false
		}
	}
	for len(c.pendingRetire) > 0 && fits(9) {
		seq := c.pendingRetire[0]
		c.pendingRetire = c.pendingRetire[1:]
		payload = appendVarint(payload, frameTypeRetireConnectionID)
		payload = appendVarint(payload, seq)
		add(fkRetireCID, seq)
	}
	for len(c.pathResponses) > 0 && fits(9) {
		payload = appendVarint(payload, frameTypePathResponse)
		payload = append(payload, c.pathResponses[0][:]...)
		c.pathResponses = c.pathResponses[1:]
		p.ackEliciting = true // not retransmitted (RFC 9000, 13.3)
	}
	for _, s := range c.sendQueue {
		if s.resetPending && fits(25) {
			payload = appendVarint(payload, frameTypeResetStream)
			payload = appendVarint(payload, s.id)
			payload = appendVarint(payload, s.sendErr.Code)
			payload = appendVarint(payload, s.maxSent)
			add(fkResetStream, s.id)
			s.resetPending = false
		}
		if s.stopPending && fits(17) {
			payload = appendVarint(payload, frameTypeStopSending)
			payload = appendVarint(payload, s.id)
			payload = appendVarint(payload, s.stopCode)
			add(fkStopSending, s.id)
			s.stopPending = false
		}
		if s.maxStreamDataPending && fits(17) {
			payload = appendVarint(payload, frameTypeMaxStreamData)
			payload = appendVarint(payload, s.id)
			payload = appendVarint(payload, s.recvMaxData)
			add(fkMaxStreamData, s.id)
			s.maxStreamDataPending = false
		}
	}
	return payload
}

func (c *Conn) appendStreamFrames(p *outPacket, payload []byte, room int) []byte {
	n := len(c.sendQueue)
	for i := 0; i < n && len(c.sendQueue) > 0 && room-len(payload) >= 24; i++ {
		s := c.sendQueue[0]
		c.sendQueue = c.sendQueue[1:]
		s.queued = false
		for room-len(payload) >= 24 {
			off, data, fin, newBytes, ok := s.nextFrame(room-len(payload), c.peerMaxData-c.sentData)
			if !ok {
				break
			}
			payload = appendStreamFrameHeader(payload, s.id, off, len(data), fin)
			payload = append(payload, data...)
			c.sentData += newBytes
			p.frames = append(p.frames, sentFrame{kind: fkStream, id: s.id, offset: off, length: uint64(len(data)), fin: fin})
			p.ackEliciting = true
		}
		if s.sendable(c.peerMaxData - c.sentData) {
			c.queueStream(s) // round robin: back of the queue
		}
	}
	return payload
}
