package quic

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"time"
)

const maxUndecryptable = 16

// handleDatagram processes one UDP datagram, which may contain several
// coalesced packets. The caller holds c.mu.
func (c *Conn) handleDatagram(d datagram) {
	switch c.state {
	case stateClosed, stateDraining:
		return
	case stateClosing:
		// Answer with another CONNECTION_CLOSE (RFC 9000, 10.2.1).
		c.closeSendPending = true
		return
	}
	c.stats.BytesReceived += uint64(len(d.data))
	if !c.isClient && !c.addressValidated {
		c.ampRecv += len(d.data)
	}
	c.processPackets(d.data, d.t)
	for c.keysChanged && c.state == stateOpen {
		// New keys may decrypt packets that arrived too early.
		c.keysChanged = false
		pending := c.undecryptable
		c.undecryptable = nil
		for _, p := range pending {
			c.processPackets(p, d.t)
		}
	}
}

func (c *Conn) processPackets(b []byte, now time.Time) {
	for len(b) > 0 && c.state == stateOpen {
		var n int
		var err error
		if b[0]&0x80 != 0 {
			n, err = c.handleLongPacket(b, now)
		} else {
			n, err = c.handleShortPacket(b, now)
		}
		if err != nil {
			c.closeWithError(err)
			return
		}
		if n <= 0 {
			return
		}
		b = b[n:]
	}
}

func (c *Conn) bufferUndecryptable(pkt []byte) {
	if len(c.undecryptable) < maxUndecryptable {
		c.undecryptable = append(c.undecryptable, bytes.Clone(pkt))
	}
}

// handleLongPacket processes the long header packet at the start of b and
// returns its length. A non-positive length drops the rest of the datagram.
func (c *Conn) handleLongPacket(b []byte, now time.Time) (int, error) {
	hdr, err := parseLongHeader(b)
	if err != nil {
		return 0, nil
	}
	if hdr.version == 0 {
		return 0, c.handleVersionNegotiation(hdr)
	}
	if hdr.version != version1 {
		return 0, nil
	}
	if !bytes.Equal(hdr.dcid, c.scid) && !(!c.isClient && bytes.Equal(hdr.dcid, c.initDCID)) {
		return hdr.end, nil
	}
	var space int
	switch hdr.typ {
	case packetTypeRetry:
		return 0, c.handleRetry(hdr, b)
	case packetTypeInitial:
		if c.isClient && len(hdr.token) > 0 {
			return hdr.end, nil // servers never send tokens in Initial packets
		}
		space = spaceInitial
	case packetTypeHandshake:
		space = spaceHandshake
	default:
		return hdr.end, nil // 0-RTT is not supported
	}
	if c.isClient && c.gotServerPacket && !bytes.Equal(hdr.scid, c.dcid) {
		return hdr.end, nil
	}
	sp := c.spaces[space]
	if sp.discarded {
		return hdr.end, nil
	}
	pkt := b[:hdr.end]
	if sp.readKeys == nil {
		c.bufferUndecryptable(pkt)
		return hdr.end, nil
	}
	truncated, pnLen, err := removeHeaderProtection(pkt, hdr.pnOffset, sp.readKeys.hp)
	if err != nil {
		return hdr.end, nil
	}
	pn := decodePacketNumber(sp.largestRecvd, truncated, pnLen)
	hdrLen := hdr.pnOffset + pnLen
	payload, err := decryptPayload(sp.readKeys, pn, pkt[:hdrLen], pkt[hdrLen:])
	if err != nil {
		c.logf("dropping undecryptable %s packet", spaceNames[space])
		return hdr.end, nil
	}
	if pkt[0]&0x0c != 0 {
		return 0, transportErr(ProtocolViolation, "reserved header bits set")
	}
	if c.isClient && !c.gotServerPacket {
		// Adopt the server's chosen connection ID (RFC 9000, 7.2).
		c.dcid = bytes.Clone(hdr.scid)
		c.gotServerPacket = true
	}
	if !c.isClient && space == spaceHandshake {
		// A Handshake packet proves the client owns its address, and the
		// server no longer needs Initial keys (RFC 9001, 4.9.1).
		c.addressValidated = true
		c.dropSpace(spaceInitial)
	}
	if err := c.processPayload(space, pn, payload, now); err != nil {
		return 0, err
	}
	return hdr.end, nil
}

func (c *Conn) handleShortPacket(b []byte, now time.Time) (int, error) {
	if len(b) < 1+cidLen || b[0]&0x40 == 0 || !bytes.Equal(b[1:1+cidLen], c.scid) {
		return 0, nil
	}
	if c.appRead == nil {
		c.bufferUndecryptable(b)
		return len(b), nil
	}
	// Check for a stateless reset before touching the packet.
	resetCandidate := len(c.peerResetToken) == 16 && len(b) >= 21 &&
		subtle.ConstantTimeCompare(b[len(b)-16:], c.peerResetToken) == 1

	sp := c.spaces[spaceApp]
	pnOffset := 1 + cidLen
	truncated, pnLen, err := removeHeaderProtection(b, pnOffset, c.appRead.hp)
	if err != nil {
		return 0, nil
	}
	pn := decodePacketNumber(sp.largestRecvd, truncated, pnLen)
	phase := b[0]&0x04 != 0
	keys := c.appRead
	switch {
	case phase == c.readPhase:
	case c.appReadPrev != nil && pn < c.readPhaseFrom:
		keys = c.appReadPrev
	default:
		keys = c.appReadNext
	}
	hdrLen := pnOffset + pnLen
	payload, err := decryptPayload(keys, pn, b[:hdrLen], b[hdrLen:])
	if err != nil {
		if resetCandidate {
			c.logf("stateless reset")
			c.terminate(ErrStatelessReset)
			return 0, nil
		}
		return 0, nil
	}
	if b[0]&0x18 != 0 {
		return 0, transportErr(ProtocolViolation, "reserved header bits set")
	}
	if keys == c.appReadNext {
		c.rotateReadKeys(phase, pn)
	}
	if err := c.processPayload(spaceApp, pn, payload, now); err != nil {
		return 0, err
	}
	return len(b), nil
}

// rotateReadKeys switches to the next 1-RTT read keys after the peer
// changed the key phase, and follows with our write keys if the peer
// initiated the update.
func (c *Conn) rotateReadKeys(phase bool, pn uint64) {
	c.appReadPrev = c.appRead
	c.appRead = c.appReadNext
	c.appReadNext = c.appRead.next()
	c.readPhase = phase
	c.readPhaseFrom = pn
	if c.writePhase != phase {
		c.appWrite = c.appWrite.next()
		c.writePhase = phase
		c.writePhaseFirstPN = -1
		c.keyGeneration++
	}
	c.logf("key update: now in phase %v", phase)
}

// initiateKeyUpdate starts a 1-RTT key update. The caller holds c.mu.
func (c *Conn) initiateKeyUpdate() error {
	if !c.handshakeConfirmed {
		return errors.New("quic: key update before the handshake is confirmed")
	}
	if c.writePhase != c.readPhase {
		return errors.New("quic: previous key update still in progress")
	}
	// After the first update, a packet protected with the current keys must
	// have been acknowledged (RFC 9001, section 6.1).
	if c.keyGeneration > 0 {
		if c.writePhaseFirstPN < 0 || c.spaces[spaceApp].largestAcked < c.writePhaseFirstPN {
			return errors.New("quic: no packet acknowledged in the current key phase yet")
		}
	}
	c.appWrite = c.appWrite.next()
	c.writePhase = !c.writePhase
	c.writePhaseFirstPN = -1
	c.keyGeneration++
	c.logf("initiated key update to phase %v", c.writePhase)
	return nil
}

// UpdateKeys initiates a 1-RTT key update (RFC 9001, section 6).
func (c *Conn) UpdateKeys() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.initiateKeyUpdate(); err != nil {
		return err
	}
	c.wake()
	return nil
}

func (c *Conn) handleVersionNegotiation(hdr *longHeader) error {
	if !c.isClient || c.gotServerPacket || !bytes.Equal(hdr.dcid, c.scid) || !bytes.Equal(hdr.scid, c.initDCID) {
		return nil
	}
	for _, v := range hdr.versions {
		if v == version1 {
			return nil // a Version Negotiation listing our version is bogus
		}
	}
	c.logf("version negotiation: server offers %#x", hdr.versions)
	c.terminate(&VersionNegotiationError{Offered: hdr.versions})
	return nil
}

func (c *Conn) handleRetry(hdr *longHeader, b []byte) error {
	if !c.isClient || c.gotRetry || c.gotServerPacket || len(hdr.token) == 0 {
		return nil
	}
	tag := retryIntegrityTag(c.odcid, b[:len(b)-16])
	if subtle.ConstantTimeCompare(tag, hdr.retryTag) != 1 {
		return nil
	}
	c.logf("received Retry, new DCID %x", hdr.scid)
	c.gotRetry = true
	c.retrySCID = bytes.Clone(hdr.scid)
	c.retryToken = bytes.Clone(hdr.token)
	c.dcid = c.retrySCID
	c.initDCID = c.retrySCID
	sp := c.spaces[spaceInitial]
	sp.writeKeys, sp.readKeys = initialKeys(c.retrySCID, true)
	// Everything sent so far has to be sent again with the new keys;
	// packet numbers keep increasing (RFC 9000, 17.2.5.3).
	for _, p := range sp.sent {
		c.cc.discard(p)
	}
	sp.sent = nil
	sp.ackElicitingInFlight = 0
	sp.crypto.resendAll()
	return nil
}

// processPayload handles the frames of a decrypted packet.
func (c *Conn) processPayload(space int, pn uint64, payload []byte, now time.Time) error {
	sp := c.spaces[space]
	if pn < sp.ackFloor || sp.recvd.contains(pn) {
		return nil // duplicate
	}
	if len(payload) == 0 {
		return transportErr(ProtocolViolation, "packet without frames")
	}
	c.stats.PacketsReceived++
	ackEliciting := false
	p := frameParser{b: payload}
	for len(p.b) > 0 {
		typ, f, err := p.next()
		if err != nil {
			return err
		}
		if space != spaceApp && !allowedInLongHeader(typ) {
			return &TransportError{Code: ProtocolViolation, FrameType: typ, Reason: "frame not allowed in " + spaceNames[space] + " packets"}
		}
		if isAckEliciting(typ) {
			ackEliciting = true
		}
		if err := c.handleFrame(space, f, now); err != nil {
			var te *TransportError
			if asTransportError(err, &te) && te.FrameType == 0 {
				te.FrameType = typ
			}
			return err
		}
		if c.state != stateOpen {
			return nil
		}
	}

	sp.recvd.add(pn, pn+1)
	if len(sp.recvd) > maxRecvRanges {
		sp.ackFloor = sp.recvd[len(sp.recvd)-maxRecvRanges].start
		sp.recvd.trimBelow(sp.ackFloor)
	}
	if int64(pn) > sp.largestRecvd {
		sp.largestRecvd = int64(pn)
		sp.largestRecvdTime = now
	}
	sp.ackPending = true
	if ackEliciting {
		sp.ackElicitingUnacked++
		if space != spaceApp || sp.ackElicitingUnacked >= 2 {
			sp.ackDeadline = now
		} else if sp.ackDeadline.IsZero() {
			sp.ackDeadline = now.Add(maxAckDelay)
		}
	}
	c.lastActivity = now
	c.ackElicitingSentNow = false
	return nil
}

func (c *Conn) handleFrame(space int, frame any, now time.Time) error {
	switch f := frame.(type) {
	case paddingFrame, pingFrame, blockedFrame:
	case ackFrame:
		return c.onAckFrame(space, f, now)
	case cryptoFrame:
		data, err := c.spaces[space].crypto.recv(f.offset, f.data)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if err := c.tls.HandleData(levelForSpace[space], data); err != nil {
				return cryptoError(err)
			}
			return c.handleTLSEvents()
		}
	case connectionCloseFrame:
		c.onPeerClose(f)
	case handshakeDoneFrame:
		if !c.isClient {
			return transportErr(ProtocolViolation, "client sent HANDSHAKE_DONE")
		}
		c.confirmHandshake()
	case newTokenFrame:
		if !c.isClient {
			return transportErr(ProtocolViolation, "client sent NEW_TOKEN")
		}
	case streamFrame:
		return c.onStreamFrame(f)
	case resetStreamFrame:
		return c.onResetStream(f)
	case stopSendingFrame:
		return c.onStopSending(f)
	case maxDataFrame:
		if f.max > c.peerMaxData {
			c.peerMaxData = f.max
			c.requeueAllStreams()
		}
	case maxStreamDataFrame:
		s, err := c.streamForFrame(f.id, true)
		if err != nil || s == nil {
			return err
		}
		if f.max > s.peerMaxData {
			s.peerMaxData = f.max
			c.queueStream(s)
		}
	case maxStreamsFrame:
		k := 0
		if !f.bidi {
			k = 1
		}
		if f.max > c.peerMaxStreams[k] {
			c.peerMaxStreams[k] = f.max
			c.broadcastStreams()
		}
	case newConnectionIDFrame:
		return c.onNewConnectionID(f)
	case retireConnectionIDFrame:
		if f.seq != 0 {
			return transportErr(ProtocolViolation, "RETIRE_CONNECTION_ID for a connection ID that was never issued")
		}
	case pathChallengeFrame:
		if len(c.pathResponses) < 4 {
			c.pathResponses = append(c.pathResponses, f.data)
		}
	case pathResponseFrame:
		// We never send PATH_CHALLENGE.
	}
	return nil
}

func asTransportError(err error, out **TransportError) bool {
	te, ok := err.(*TransportError)
	if ok {
		*out = te
	}
	return ok
}

func (c *Conn) onNewConnectionID(f newConnectionIDFrame) error {
	if len(c.dcid) == 0 {
		return transportErr(ProtocolViolation, "NEW_CONNECTION_ID with a zero-length connection ID in use")
	}
	if len(c.peerCIDs) == 0 {
		c.peerCIDs = []peerCID{{0, c.dcid}}
	}
	for _, p := range c.peerCIDs {
		if p.seq == f.seq {
			if !bytes.Equal(p.cid, f.cid) {
				return transportErr(ProtocolViolation, "NEW_CONNECTION_ID reuses a sequence number")
			}
			return nil
		}
	}
	if f.seq < c.retirePriorTo {
		c.pendingRetire = append(c.pendingRetire, f.seq)
		return nil
	}
	c.peerCIDs = append(c.peerCIDs, peerCID{f.seq, bytes.Clone(f.cid)})
	if f.retirePriorTo > c.retirePriorTo {
		c.retirePriorTo = f.retirePriorTo
		kept := c.peerCIDs[:0]
		for _, p := range c.peerCIDs {
			if p.seq < c.retirePriorTo {
				c.pendingRetire = append(c.pendingRetire, p.seq)
			} else {
				kept = append(kept, p)
			}
		}
		c.peerCIDs = kept
		if c.activePeerSeq < c.retirePriorTo && len(c.peerCIDs) > 0 {
			best := c.peerCIDs[0]
			for _, p := range c.peerCIDs {
				if p.seq < best.seq {
					best = p
				}
			}
			c.activePeerSeq = best.seq
			c.dcid = best.cid
			c.logf("switched to peer connection ID %x (seq %d)", best.cid, best.seq)
		}
	}
	if len(c.peerCIDs) > activeConnIDLimit {
		return transportErr(ConnectionIDLimitError, "peer issued more than %d connection IDs", activeConnIDLimit)
	}
	return nil
}

// Stream frames.

// streamForFrame returns the stream a frame refers to, opening peer
// streams implicitly. A nil stream without error means the stream is
// already closed and the frame should be ignored. needSend selects frames
// that act on our sending part.
func (c *Conn) streamForFrame(id uint64, needSend bool) (*Stream, error) {
	local := streamIsServer(id) != c.isClient
	uni := streamIsUni(id)
	k := 0
	if uni {
		k = 1
	}
	if uni && local != needSend {
		return nil, transportErr(StreamStateError, "frame for the wrong direction of unidirectional stream %d", id)
	}
	idx := streamIndex(id)
	if local {
		if idx >= c.nextLocal[k] {
			return nil, transportErr(StreamStateError, "frame for stream %d which was not opened", id)
		}
		return c.streams[id], nil
	}
	if idx >= c.maxPeerStreams[k] {
		return nil, transportErr(StreamLimitError, "peer opened stream %d beyond the limit", id)
	}
	for c.peerOpened[k] <= idx {
		nid := streamID(c.peerOpened[k], c.isClient, uni)
		c.peerOpened[k]++
		limit := uint64(0)
		if !uni {
			limit = c.peerParams.maxStreamDataBidiLocal
		}
		s := newStream(c, nid, !uni, true, limit, c.config.InitialStreamReceiveWindow)
		c.streams[nid] = s
		c.acceptQueue[k] = append(c.acceptQueue[k], s)
		c.broadcastStreams()
	}
	return c.streams[id], nil
}

func (c *Conn) onStreamFrame(f streamFrame) error {
	s, err := c.streamForFrame(f.id, false)
	if err != nil || s == nil {
		return err
	}
	end := f.offset + uint64(len(f.data))
	if s.finalKnown && (end > s.finalSize || (f.fin && end != s.finalSize)) {
		return transportErr(FinalSizeError, "stream %d data beyond its final size", f.id)
	}
	if f.fin && end < s.highestRecv {
		return transportErr(FinalSizeError, "stream %d final size below received data", f.id)
	}
	if end > s.recvMaxData {
		return transportErr(FlowControlError, "stream %d exceeded its flow control limit", f.id)
	}
	if end > s.highestRecv {
		delta := end - s.highestRecv
		s.highestRecv = end
		c.recvData += delta
		if c.recvData > c.recvMaxData {
			return transportErr(FlowControlError, "connection flow control limit exceeded")
		}
		if s.readCanceled || s.recvErr != nil {
			c.consumedData += delta
			c.updateConnWindow()
		}
	}
	if f.fin {
		s.finalKnown, s.finalSize = true, end
	}
	if s.readCanceled || s.recvErr != nil {
		return nil
	}
	s.insert(f.offset, f.data)
	if f.fin {
		s.signal()
	}
	return nil
}

func (c *Conn) onResetStream(f resetStreamFrame) error {
	s, err := c.streamForFrame(f.id, false)
	if err != nil || s == nil {
		return err
	}
	if (s.finalKnown && f.finalSize != s.finalSize) || f.finalSize < s.highestRecv {
		return transportErr(FinalSizeError, "RESET_STREAM changes the final size of stream %d", f.id)
	}
	if f.finalSize > s.recvMaxData {
		return transportErr(FlowControlError, "RESET_STREAM final size exceeds the flow control limit")
	}
	c.recvData += f.finalSize - s.highestRecv
	if c.recvData > c.recvMaxData {
		return transportErr(FlowControlError, "connection flow control limit exceeded")
	}
	s.highestRecv = f.finalSize
	s.finalKnown, s.finalSize = true, f.finalSize
	if s.recvErr == nil {
		s.recvErr = &StreamError{StreamID: s.id, Code: f.code, Remote: true}
		c.consumedData += s.highestRecv - s.readOffset
		c.updateConnWindow()
		s.readOffset = s.highestRecv
		s.recvBuf, s.segments = nil, nil
		s.signal()
	}
	c.maybeRelease(s)
	return nil
}

func (c *Conn) onStopSending(f stopSendingFrame) error {
	s, err := c.streamForFrame(f.id, true)
	if err != nil || s == nil {
		return err
	}
	s.resetSendLocked(f.code, true)
	return nil
}

// consumed accounts for n bytes the application read (or discarded) from s
// and schedules window updates. The caller holds c.mu.
func (c *Conn) consumed(s *Stream, n uint64) {
	c.consumedData += n
	window := c.config.InitialStreamReceiveWindow
	if !s.finalKnown && !s.readCanceled && s.recvMaxData-s.readOffset < window/2 {
		s.recvMaxData = s.readOffset + window
		s.maxStreamDataPending = true
		c.queueStream(s)
	}
	c.updateConnWindow()
}

func (c *Conn) updateConnWindow() {
	window := c.config.InitialConnectionReceiveWindow
	if c.recvMaxData-c.consumedData < window/2 {
		c.recvMaxData = c.consumedData + window
		c.maxDataPending = true
		c.wake()
	}
}

// maybeRelease forgets a finished stream and returns its credit to the
// peer if the peer opened it.
func (c *Conn) maybeRelease(s *Stream) {
	if s.released || !s.sendDone() || !s.recvDone() {
		return
	}
	s.released = true
	delete(c.streams, s.id)
	if streamIsServer(s.id) == c.isClient { // peer-initiated
		k := 0
		if streamIsUni(s.id) {
			k = 1
		}
		c.maxPeerStreams[k]++
		c.maxStreamsPending[k] = true
		c.wake()
	}
}

func (c *Conn) queueStream(s *Stream) {
	if !s.queued && !s.released {
		s.queued = true
		c.sendQueue = append(c.sendQueue, s)
	}
}

func (c *Conn) requeueAllStreams() {
	for _, s := range c.streams {
		if s.hasWork() {
			c.queueStream(s)
		}
	}
}
