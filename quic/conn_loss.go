package quic

import "time"

// ACK processing and loss detection (RFC 9002, appendix A).

func ackContains(ranges []span, pn uint64) bool {
	for _, r := range ranges {
		if pn >= r.end {
			return false // ranges are descending
		}
		if pn >= r.start {
			return true
		}
	}
	return false
}

func (c *Conn) onAckFrame(space int, f ackFrame, now time.Time) error {
	sp := c.spaces[space]
	largest := f.largest()
	if largest >= sp.nextPN {
		return transportErr(ProtocolViolation, "ACK for packet %d that was never sent", largest)
	}
	if int64(largest) > sp.largestAcked {
		sp.largestAcked = int64(largest)
	}

	var newly []*sentPacket
	kept := sp.sent[:0]
	for _, p := range sp.sent {
		if ackContains(f.ranges, p.pn) {
			newly = append(newly, p)
		} else {
			kept = append(kept, p)
		}
	}
	clear(sp.sent[len(kept):])
	sp.sent = kept
	if len(newly) == 0 {
		return nil
	}

	last := newly[len(newly)-1]
	if last.pn == largest {
		eliciting := false
		for _, p := range newly {
			eliciting = eliciting || p.ackEliciting
		}
		if eliciting {
			var ackDelay time.Duration
			if space == spaceApp && c.peerParams != nil {
				ackDelay = time.Duration(f.ackDelay<<c.peerParams.ackDelayExponent) * time.Microsecond
				if c.handshakeConfirmed {
					ackDelay = min(ackDelay, c.peerParams.maxAckDelay)
				}
			}
			c.rtt.update(now.Sub(last.sentTime), ackDelay)
		}
	}

	for _, p := range newly {
		c.cc.onAcked(p)
		if p.ackEliciting {
			sp.ackElicitingInFlight--
		}
		for _, fr := range p.frames {
			c.onFrameAcked(space, fr)
		}
	}
	if space == spaceApp && c.isClient && c.handshakeComplete {
		// An acknowledged 1-RTT packet also confirms the handshake.
		c.confirmHandshake()
	}
	c.detectLostPackets(space, now)
	if c.peerCompletedAddressValidation() {
		c.ptoCount = 0
	}
	return nil
}

func (c *Conn) onFrameAcked(space int, f sentFrame) {
	switch f.kind {
	case fkCrypto:
		if sp := c.spaces[space]; !sp.discarded {
			sp.crypto.ack(f.offset, f.length)
		}
	case fkStream:
		if s := c.streams[f.id]; s != nil {
			s.onAcked(f.offset, f.length, f.fin)
			c.maybeRelease(s)
		}
	case fkResetStream:
		if s := c.streams[f.id]; s != nil {
			s.resetAcked = true
			c.maybeRelease(s)
		}
	case fkAck:
		// The peer has seen our acknowledgment up to f.id; older packet
		// numbers need not be reported again.
		sp := c.spaces[space]
		if f.id+1 > sp.ackFloor {
			sp.ackFloor = f.id + 1
			sp.recvd.trimBelow(sp.ackFloor)
		}
	}
}

// onFrameLost queues the content of a lost (or probed) packet again.
func (c *Conn) onFrameLost(space int, f sentFrame) {
	switch f.kind {
	case fkCrypto:
		if sp := c.spaces[space]; !sp.discarded {
			sp.crypto.requeue(f.offset, f.length)
		}
	case fkStream:
		if s := c.streams[f.id]; s != nil {
			s.onLost(f.offset, f.length, f.fin)
			c.queueStream(s)
		}
	case fkMaxData:
		c.maxDataPending = true
	case fkMaxStreamData:
		if s := c.streams[f.id]; s != nil && !s.finalKnown && !s.readCanceled {
			s.maxStreamDataPending = true
			c.queueStream(s)
		}
	case fkMaxStreamsBidi:
		c.maxStreamsPending[0] = true
	case fkMaxStreamsUni:
		c.maxStreamsPending[1] = true
	case fkHandshakeDone:
		c.handshakeDonePend = true
	case fkResetStream:
		if s := c.streams[f.id]; s != nil && !s.resetAcked {
			s.resetPending = true
			c.queueStream(s)
		}
	case fkStopSending:
		if s := c.streams[f.id]; s != nil && s.recvErr == nil && !(s.finalKnown && s.highestRecv == s.finalSize) {
			s.stopPending = true
			c.queueStream(s)
		}
	case fkRetireCID:
		c.pendingRetire = append(c.pendingRetire, f.id)
	}
}

func (c *Conn) detectLostPackets(space int, now time.Time) {
	sp := c.spaces[space]
	sp.lossTime = time.Time{}
	if sp.largestAcked < 0 {
		return
	}
	largestAcked := uint64(sp.largestAcked)
	lossDelay := c.rtt.lossDelay()
	lostSendTime := now.Add(-lossDelay)
	var lost []*sentPacket
	kept := sp.sent[:0]
	for _, p := range sp.sent {
		if p.pn > largestAcked {
			kept = append(kept, p)
			continue
		}
		if !p.sentTime.After(lostSendTime) || largestAcked >= p.pn+packetThreshold {
			lost = append(lost, p)
			continue
		}
		if t := p.sentTime.Add(lossDelay); sp.lossTime.IsZero() || t.Before(sp.lossTime) {
			sp.lossTime = t
		}
		kept = append(kept, p)
	}
	clear(sp.sent[len(kept):])
	sp.sent = kept

	var lastLost time.Time
	for _, p := range lost {
		c.cc.onLost(p)
		if p.ackEliciting {
			sp.ackElicitingInFlight--
			c.stats.PacketsLost++
		}
		if p.inFlight {
			lastLost = p.sentTime
		}
		for _, fr := range p.frames {
			c.onFrameLost(space, fr)
		}
	}
	if !lastLost.IsZero() {
		c.cc.onCongestionEvent(lastLost, now)
		c.logf("%d %s packets lost, cwnd now %d", len(lost), spaceNames[space], c.cc.window)
	}
}

func (c *Conn) peerCompletedAddressValidation() bool {
	if !c.isClient {
		return true
	}
	return c.handshakeConfirmed || c.spaces[spaceHandshake].largestAcked >= 0
}

func (c *Conn) ptoDuration() time.Duration {
	d := c.rtt.pto()
	if c.peerParams != nil {
		d += c.peerParams.maxAckDelay
	}
	return d
}

func (c *Conn) ackElicitingInFlight() bool {
	for _, sp := range c.spaces {
		if sp.ackElicitingInFlight > 0 {
			return true
		}
	}
	return false
}

// ptoDeadline returns when the probe timeout fires and for which space.
func (c *Conn) ptoDeadline() (time.Time, int) {
	backoff := time.Duration(1) << min(c.ptoCount, 16)
	duration := c.rtt.pto() * backoff
	if !c.ackElicitingInFlight() {
		if c.peerCompletedAddressValidation() {
			return time.Time{}, 0
		}
		// Client anti-deadlock probe (RFC 9002, 6.2.2.1).
		space := spaceInitial
		if c.spaces[spaceHandshake].writeKeys != nil {
			space = spaceHandshake
		}
		base := c.lastProbe
		for _, sp := range c.spaces {
			if sp.lastAckElicitingSent.After(base) {
				base = sp.lastAckElicitingSent
			}
		}
		if base.IsZero() {
			return time.Time{}, 0 // nothing sent yet
		}
		return base.Add(duration), space
	}
	var best time.Time
	bestSpace := 0
	for space, sp := range c.spaces {
		if sp.ackElicitingInFlight == 0 {
			continue
		}
		d := duration
		if space == spaceApp {
			if !c.handshakeConfirmed {
				continue
			}
			if c.peerParams != nil {
				d += c.peerParams.maxAckDelay * backoff
			}
		}
		if t := sp.lastAckElicitingSent.Add(d); best.IsZero() || t.Before(best) {
			best, bestSpace = t, space
		}
	}
	return best, bestSpace
}

func (c *Conn) earliestLossTime() (time.Time, int) {
	var best time.Time
	bestSpace := 0
	for space, sp := range c.spaces {
		if !sp.lossTime.IsZero() && (best.IsZero() || sp.lossTime.Before(best)) {
			best, bestSpace = sp.lossTime, space
		}
	}
	return best, bestSpace
}

func (c *Conn) lossDetectionDeadline() time.Time {
	if t, _ := c.earliestLossTime(); !t.IsZero() {
		return t
	}
	if !c.isClient && !c.addressValidated && 3*c.ampRecv <= c.ampSent {
		return time.Time{} // amplification limited: we could not send anyway
	}
	t, _ := c.ptoDeadline()
	return t
}

func (c *Conn) onLossDetectionTimeout(now time.Time) {
	if t, space := c.earliestLossTime(); !t.IsZero() {
		if !now.Before(t) {
			c.detectLostPackets(space, now)
		}
		return
	}
	t, space := c.ptoDeadline()
	if t.IsZero() || now.Before(t) {
		return
	}
	c.ptoCount++
	c.lastProbe = now
	c.queueProbe(space)
	c.logf("PTO #%d in %s space", c.ptoCount, spaceNames[space])
}

// queueProbe arranges for ack-eliciting probe packets in a space, resending
// the data of the oldest outstanding packets (RFC 9002, 6.2.4).
func (c *Conn) queueProbe(space int) {
	sp := c.spaces[space]
	n := 0
	for _, p := range sp.sent {
		if !p.ackEliciting {
			continue
		}
		for _, fr := range p.frames {
			c.onFrameLost(space, fr)
		}
		if n++; n == 2 {
			break
		}
	}
	if space == spaceApp {
		c.probes[space] = 2
	} else {
		c.probes[space] = 1
	}
}
