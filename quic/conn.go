package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// Packet number spaces (RFC 9000, section 12.3).
const (
	spaceInitial = iota
	spaceHandshake
	spaceApp
	numSpaces
)

var spaceNames = [numSpaces]string{"Initial", "Handshake", "1-RTT"}

func spaceForLevel(l tls13.Level) int {
	switch l {
	case tls13.LevelInitial:
		return spaceInitial
	case tls13.LevelHandshake:
		return spaceHandshake
	}
	return spaceApp
}

var levelForSpace = [numSpaces]tls13.Level{tls13.LevelInitial, tls13.LevelHandshake, tls13.LevelApplication}

type pnSpace struct {
	writeKeys *packetKeys // unused for spaceApp, see Conn.appWrite
	readKeys  *packetKeys // unused for spaceApp, see Conn.appRead
	discarded bool
	crypto    cryptoStream

	// Sending.
	nextPN               uint64
	largestAcked         int64
	sent                 []*sentPacket // ascending packet numbers
	lossTime             time.Time
	lastAckElicitingSent time.Time
	ackElicitingInFlight int

	// Receiving.
	recvd               rangeSet
	ackFloor            uint64 // packets below this are treated as duplicates
	largestRecvd        int64
	largestRecvdTime    time.Time
	ackPending          bool // received packets not yet acknowledged
	ackElicitingUnacked int
	ackDeadline         time.Time
}

type connState int

const (
	stateOpen connState = iota
	stateClosing
	stateDraining
	stateClosed
)

type datagram struct {
	data []byte
	t    time.Time
}

type peerCID struct {
	seq uint64
	cid []byte
}

const (
	// maxAckDelay is the max_ack_delay we advertise.
	maxAckDelay = 25 * time.Millisecond
	// ackDelayExponent is the ack_delay_exponent we advertise and use.
	ackDelayExponent = 3
	// activeConnIDLimit is the active_connection_id_limit we advertise.
	activeConnIDLimit = 4
	// maxRecvRanges bounds the received packet number ranges kept for ACKs.
	maxRecvRanges = 32
	// maxDatagramsPerRound bounds the datagrams built per loop iteration.
	maxDatagramsPerRound = 32
)

// Conn is a QUIC connection.
type Conn struct {
	isClient bool
	config   *Config
	tls      *tls13.QUICConn
	logf     func(format string, args ...any)

	pconn    net.PacketConn
	remote   net.Addr
	listener *Listener // server side
	recvCh   chan datagram
	wakeCh   chan struct{}

	mu sync.Mutex

	// Connection IDs.
	scid       []byte // ours
	dcid       []byte // the peer's, used as Destination Connection ID
	odcid      []byte // the client's first Destination Connection ID
	initDCID   []byte // DCID of the client's Initial packets (odcid or the Retry SCID)
	peerSCID   []byte // server: client's SCID, to check initial_source_connection_id
	retrySCID  []byte
	retryToken []byte
	gotRetry   bool
	// gotServerPacket is set once the client processed a server packet and
	// adopted its Source Connection ID.
	gotServerPacket bool
	peerCIDs        []peerCID
	activePeerSeq   uint64
	retirePriorTo   uint64
	pendingRetire   []uint64

	spaces [numSpaces]*pnSpace
	// 1-RTT keys and key update state (RFC 9001, section 6).
	appRead       *packetKeys
	appReadNext   *packetKeys
	appReadPrev   *packetKeys
	readPhase     bool
	readPhaseFrom uint64 // first packet number of the current read phase
	appWrite      *packetKeys
	writePhase    bool
	// writePhaseFirstPN is the first packet number sent in the current
	// write phase, or -1.
	writePhaseFirstPN int64
	keyGeneration     int // number of 1-RTT write key updates so far
	keysChanged       bool
	undecryptable     [][]byte

	handshakeComplete   bool
	handshakeConfirmed  bool
	handshakeDonePend   bool
	handshakeDoneCh     chan struct{}
	handshakeDeadline   time.Time
	addressValidated    bool
	ampRecv, ampSent    int // bytes for the anti-amplification limit
	peerParams          *transportParameters
	localParams         transportParameters
	peerResetToken      []byte
	idleTimeout         time.Duration
	lastActivity        time.Time
	ackElicitingSentNow bool // ack-eliciting packet sent since last receipt
	pingPending         bool

	rtt       rttStats
	cc        congestionController
	ptoCount  int
	probes    [numSpaces]int
	lastProbe time.Time

	// Flow control.
	peerMaxData    uint64
	sentData       uint64
	recvMaxData    uint64
	recvData       uint64
	consumedData   uint64
	maxDataPending bool

	// Streams.
	streams           map[uint64]*Stream
	sendQueue         []*Stream
	nextLocal         [2]uint64 // [bidi, uni] next local stream index
	peerMaxStreams    [2]uint64 // streams we may open
	peerOpened        [2]uint64 // streams the peer has opened
	maxPeerStreams    [2]uint64 // streams the peer may open (advertised)
	maxStreamsPending [2]bool
	acceptQueue       [2][]*Stream
	streamsChanged    chan struct{}
	pathResponses     [][8]byte

	// Closing.
	state            connState
	closeErr         error
	closeFrame       *connectionCloseFrame
	closeSendPending bool
	closeDeadline    time.Time
	closingCh        chan struct{} // closed when the connection leaves stateOpen
	closeSentCh      chan struct{} // closed once our CONNECTION_CLOSE went out
	closeSent        bool
	done             chan struct{} // closed when the connection is terminated

	stats Stats
}

// Stats reports connection counters and estimates.
type Stats struct {
	PacketsSent      uint64
	PacketsReceived  uint64
	PacketsLost      uint64
	BytesSent        uint64
	BytesReceived    uint64
	SmoothedRTT      time.Duration
	MinRTT           time.Duration
	CongestionWindow int
}

// ConnectionState describes an established connection.
type ConnectionState struct {
	TLS       tls13.ConnectionState
	Version   uint32
	UsedRetry bool
}

func randomCID() []byte {
	b := make([]byte, cidLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newConn(isClient bool, config *Config, pconn net.PacketConn, remote net.Addr) *Conn {
	cfg := config.withDefaults()
	c := &Conn{
		isClient:        isClient,
		config:          cfg,
		pconn:           pconn,
		remote:          remote,
		recvCh:          make(chan datagram, 256),
		wakeCh:          make(chan struct{}, 1),
		scid:            randomCID(),
		streams:         map[uint64]*Stream{},
		streamsChanged:  make(chan struct{}),
		handshakeDoneCh: make(chan struct{}),
		closingCh:       make(chan struct{}),
		closeSentCh:     make(chan struct{}),
		done:            make(chan struct{}),
		rtt:             newRTTStats(),
		cc:              newCongestionController(),
		idleTimeout:     cfg.MaxIdleTimeout,
		recvMaxData:     cfg.InitialConnectionReceiveWindow,
		maxPeerStreams:  [2]uint64{uint64(cfg.MaxIncomingStreams), uint64(cfg.MaxIncomingUniStreams)},
	}
	for i := range c.spaces {
		c.spaces[i] = &pnSpace{largestAcked: -1, largestRecvd: -1}
	}
	c.writePhaseFirstPN = -1
	now := time.Now()
	c.lastActivity = now
	c.handshakeDeadline = now.Add(cfg.HandshakeTimeout)
	if cfg.Logf != nil {
		role := "server"
		if isClient {
			role = "client"
		}
		c.logf = func(format string, args ...any) { cfg.Logf(role+": "+format, args...) }
	} else {
		c.logf = func(string, ...any) {}
	}
	return c
}

func (c *Conn) buildLocalParams() {
	cfg := c.config
	p := defaultTransportParameters()
	p.maxIdleTimeout = cfg.MaxIdleTimeout
	p.maxUDPPayloadSize = 1472
	p.initialMaxData = cfg.InitialConnectionReceiveWindow
	p.maxStreamDataBidiLocal = cfg.InitialStreamReceiveWindow
	p.maxStreamDataBidiRem = cfg.InitialStreamReceiveWindow
	p.maxStreamDataUni = cfg.InitialStreamReceiveWindow
	p.maxStreamsBidi = c.maxPeerStreams[0]
	p.maxStreamsUni = c.maxPeerStreams[1]
	p.ackDelayExponent = ackDelayExponent
	p.maxAckDelay = maxAckDelay
	p.disableActiveMigration = true
	p.activeConnIDLimit = activeConnIDLimit
	p.initialSourceCID = c.scid
	if !c.isClient {
		p.originalDestinationCID = c.odcid
		if c.gotRetry {
			p.retrySourceCID, p.hasRetrySourceCID = c.retrySCID, true
		}
	}
	c.localParams = p
}

// wake makes the connection goroutine re-evaluate what to send.
func (c *Conn) wake() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

// deliver hands a received datagram to the connection goroutine.
func (c *Conn) deliver(d datagram) {
	select {
	case c.recvCh <- d:
	default: // queue full: drop, as a congested network would
	}
}

func (c *Conn) broadcastStreams() {
	close(c.streamsChanged)
	c.streamsChanged = make(chan struct{})
}

// run is the connection's event loop.
func (c *Conn) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.mu.Lock()
		now := time.Now()
		c.onTimers(now)
		var out [][]byte
		if c.state != stateClosed {
			out = c.buildDatagrams(now)
		}
		deadline := c.nextDeadline()
		closed := c.state == stateClosed
		c.mu.Unlock()

		for _, d := range out {
			c.pconn.WriteTo(d, c.remote)
		}
		if closed {
			c.cleanup()
			return
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if deadline.IsZero() {
			timer.Reset(time.Hour)
		} else {
			timer.Reset(max(time.Until(deadline), 0))
		}
		select {
		case d := <-c.recvCh:
			c.mu.Lock()
			c.handleDatagram(d)
			for i := 0; i < 32; i++ {
				select {
				case d = <-c.recvCh:
					c.handleDatagram(d)
					continue
				default:
				}
				break
			}
			c.mu.Unlock()
		case <-timer.C:
		case <-c.wakeCh:
		}
	}
}

func (c *Conn) cleanup() {
	if c.listener != nil {
		c.listener.removeConn(c)
	} else {
		c.pconn.Close()
	}
}

// onTimers handles expired timers. The caller holds c.mu.
func (c *Conn) onTimers(now time.Time) {
	switch c.state {
	case stateClosed:
		return
	case stateClosing, stateDraining:
		if !now.Before(c.closeDeadline) {
			c.terminate(nil)
		}
		return
	}
	if !c.handshakeComplete && !now.Before(c.handshakeDeadline) {
		c.logf("handshake timeout")
		c.terminate(ErrHandshakeTimeout)
		return
	}
	if !now.Before(c.lastActivity.Add(c.effectiveIdleTimeout())) {
		c.logf("idle timeout")
		c.terminate(ErrIdleTimeout)
		return
	}
	if d := c.lossDetectionDeadline(); !d.IsZero() && !now.Before(d) {
		c.onLossDetectionTimeout(now)
	}
	if p := c.config.KeepAlivePeriod; p > 0 && c.handshakeComplete && !now.Before(c.lastActivity.Add(p)) && !c.pingPending {
		c.pingPending = true
	}
}

func (c *Conn) effectiveIdleTimeout() time.Duration {
	return max(c.idleTimeout, 3*c.ptoDuration())
}

func (c *Conn) nextDeadline() time.Time {
	var d time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (d.IsZero() || t.Before(d)) {
			d = t
		}
	}
	switch c.state {
	case stateClosed:
		return time.Time{}
	case stateClosing, stateDraining:
		return c.closeDeadline
	}
	if !c.handshakeComplete {
		consider(c.handshakeDeadline)
	}
	consider(c.lastActivity.Add(c.effectiveIdleTimeout()))
	consider(c.lossDetectionDeadline())
	for _, sp := range c.spaces {
		if sp.ackElicitingUnacked > 0 && !sp.discarded {
			consider(sp.ackDeadline)
		}
	}
	if p := c.config.KeepAlivePeriod; p > 0 && c.handshakeComplete {
		consider(c.lastActivity.Add(p))
	}
	return d
}

// terminate ends the connection immediately. The caller holds c.mu.
func (c *Conn) terminate(err error) {
	if c.state == stateClosed {
		return
	}
	if c.closeErr == nil {
		if err == nil {
			err = ErrClosed
		}
		c.closeErr = err
	}
	if c.state == stateOpen {
		close(c.closingCh)
	}
	c.state = stateClosed
	if !c.closeSent {
		c.closeSent = true
		close(c.closeSentCh)
	}
	close(c.done)
	for _, s := range c.streams {
		s.signal()
	}
	c.broadcastStreams()
}

// closeLocal starts an immediate close with our CONNECTION_CLOSE frame.
func (c *Conn) closeLocal(err error, frame *connectionCloseFrame) {
	if c.state != stateOpen {
		return
	}
	c.logf("closing: %v", err)
	c.closeErr = err
	c.closeFrame = frame
	c.closeSendPending = true
	c.state = stateClosing
	c.closeDeadline = time.Now().Add(3 * c.ptoDuration())
	close(c.closingCh)
	for _, s := range c.streams {
		s.signal()
	}
	c.broadcastStreams()
	c.wake()
}

// closeWithError closes the connection because of a local error.
func (c *Conn) closeWithError(err error) {
	var te *TransportError
	if !errors.As(err, &te) {
		te = &TransportError{Code: InternalError, Reason: err.Error()}
	}
	frame := &connectionCloseFrame{code: uint64(te.Code), frameType: te.FrameType, reason: te.Reason}
	if te.TLSError != nil {
		frame.reason = ""
	}
	c.closeLocal(te, frame)
}

// cryptoError converts a TLS failure into a CRYPTO_ERROR.
func cryptoError(err error) *TransportError {
	return &TransportError{Code: cryptoErrorBase + TransportErrorCode(tls13.AlertCode(err)), TLSError: err}
}

func (c *Conn) onPeerClose(f connectionCloseFrame) {
	var err error
	if f.app {
		err = &ApplicationError{Code: f.code, Reason: f.reason, Remote: true}
	} else {
		err = &TransportError{Code: TransportErrorCode(f.code), FrameType: f.frameType, Reason: f.reason, Remote: true}
	}
	c.logf("peer closed: %v", err)
	switch c.state {
	case stateOpen:
		c.closeErr = err
		close(c.closingCh)
	case stateClosing:
	default:
		return
	}
	c.state = stateDraining
	c.closeDeadline = time.Now().Add(3 * c.ptoDuration())
	if !c.closeSent {
		// Nothing more will be sent in the draining state.
		c.closeSent = true
		close(c.closeSentCh)
	}
	for _, s := range c.streams {
		s.signal()
	}
	c.broadcastStreams()
}

// handleTLSEvents applies the events produced by the TLS handshake. The
// caller holds c.mu.
func (c *Conn) handleTLSEvents() error {
	for {
		e := c.tls.NextEvent()
		switch e.Kind {
		case tls13.QUICNoEvent:
			return nil
		case tls13.QUICWriteData:
			c.spaces[spaceForLevel(e.Level)].crypto.write(e.Data)
		case tls13.QUICSetReadSecret:
			keys := newPacketKeys(e.Suite, e.Secret, nil)
			if s := spaceForLevel(e.Level); s == spaceApp {
				c.appRead, c.appReadNext = keys, keys.next()
			} else {
				c.spaces[s].readKeys = keys
			}
			c.keysChanged = true
			c.logf("installed %s read keys (%s)", e.Level, e.Suite.Name)
		case tls13.QUICSetWriteSecret:
			keys := newPacketKeys(e.Suite, e.Secret, nil)
			if s := spaceForLevel(e.Level); s == spaceApp {
				c.appWrite = keys
			} else {
				c.spaces[s].writeKeys = keys
			}
			c.logf("installed %s write keys (%s)", e.Level, e.Suite.Name)
		case tls13.QUICTransportParameters:
			if err := c.applyPeerParams(e.Data); err != nil {
				return err
			}
		case tls13.QUICHandshakeDone:
			c.onHandshakeComplete()
		}
	}
}

func (c *Conn) applyPeerParams(data []byte) error {
	p, err := parseTransportParameters(data, c.isClient)
	if err != nil {
		return err
	}
	bad := func(what string) error {
		return transportErr(TransportParameterError, "%s does not match", what)
	}
	if c.isClient {
		if string(p.originalDestinationCID) != string(c.odcid) {
			return bad("original_destination_connection_id")
		}
		if string(p.initialSourceCID) != string(c.dcid) {
			return bad("initial_source_connection_id")
		}
		if c.gotRetry != p.hasRetrySourceCID || (c.gotRetry && string(p.retrySourceCID) != string(c.retrySCID)) {
			return bad("retry_source_connection_id")
		}
		c.peerResetToken = p.statelessResetToken
	} else if string(p.initialSourceCID) != string(c.peerSCID) {
		return bad("initial_source_connection_id")
	}
	c.peerParams = p
	c.peerMaxData = p.initialMaxData
	c.peerMaxStreams = [2]uint64{p.maxStreamsBidi, p.maxStreamsUni}
	if p.maxIdleTimeout > 0 && p.maxIdleTimeout < c.idleTimeout {
		c.idleTimeout = p.maxIdleTimeout
	}
	c.logf("peer transport parameters: %v", p)
	return nil
}

func (c *Conn) onHandshakeComplete() {
	c.handshakeComplete = true
	close(c.handshakeDoneCh)
	st := c.tls.ConnectionState()
	c.logf("handshake complete: %s, %v, ALPN %q", tls13.CipherSuiteName(st.CipherSuite), st.CurveID, st.NegotiatedProtocol)
	if !c.isClient {
		// The server's handshake is confirmed as soon as it completes
		// (RFC 9001, section 4.1.2).
		c.handshakeDonePend = true
		c.confirmHandshake()
		if c.listener != nil {
			c.listener.queueAccept(c)
		}
	}
}

func (c *Conn) confirmHandshake() {
	if c.handshakeConfirmed {
		return
	}
	c.handshakeConfirmed = true
	c.dropSpace(spaceHandshake)
	c.logf("handshake confirmed")
}

// dropSpace discards the keys and state of a packet number space.
func (c *Conn) dropSpace(space int) {
	sp := c.spaces[space]
	if sp.discarded {
		return
	}
	sp.discarded = true
	for _, p := range sp.sent {
		c.cc.discard(p)
	}
	sp.sent = nil
	sp.ackElicitingInFlight = 0
	sp.lossTime = time.Time{}
	sp.readKeys, sp.writeKeys = nil, nil
	sp.crypto = cryptoStream{}
	sp.ackPending = false
	sp.ackElicitingUnacked = 0
	c.probes[space] = 0
	c.ptoCount = 0
	c.logf("discarded %s keys", spaceNames[space])
}

// Public API.

// OpenStream opens a bidirectional stream without blocking. It fails if
// the peer's stream limit is reached.
func (c *Conn) OpenStream() (*Stream, error) { return c.openStream(context.Background(), false, false) }

// OpenStreamSync opens a bidirectional stream, waiting for stream credit.
func (c *Conn) OpenStreamSync(ctx context.Context) (*Stream, error) {
	return c.openStream(ctx, false, true)
}

// OpenUniStream opens a unidirectional (send-only) stream without blocking.
func (c *Conn) OpenUniStream() (*Stream, error) {
	return c.openStream(context.Background(), true, false)
}

// OpenUniStreamSync opens a unidirectional stream, waiting for credit.
func (c *Conn) OpenUniStreamSync(ctx context.Context) (*Stream, error) {
	return c.openStream(ctx, true, true)
}

// ErrStreamLimit is returned by OpenStream when the peer allows no more
// streams.
var ErrStreamLimit = errors.New("quic: peer's stream limit reached")

func (c *Conn) openStream(ctx context.Context, uni, block bool) (*Stream, error) {
	k := 0
	if uni {
		k = 1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.closeErr != nil {
			return nil, c.closeErr
		}
		if c.peerParams == nil {
			return nil, errors.New("quic: handshake not complete")
		}
		if c.nextLocal[k] < c.peerMaxStreams[k] {
			id := streamID(c.nextLocal[k], !c.isClient, uni)
			c.nextLocal[k]++
			limit := c.peerParams.maxStreamDataBidiRem
			if uni {
				limit = c.peerParams.maxStreamDataUni
			}
			s := newStream(c, id, true, !uni, limit, c.config.InitialStreamReceiveWindow)
			c.streams[id] = s
			return s, nil
		}
		if !block {
			return nil, ErrStreamLimit
		}
		ch := c.streamsChanged
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			c.mu.Lock()
			return nil, ctx.Err()
		}
		c.mu.Lock()
	}
}

// AcceptStream waits for the peer to open a bidirectional stream.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) { return c.accept(ctx, 0) }

// AcceptUniStream waits for the peer to open a unidirectional stream.
func (c *Conn) AcceptUniStream(ctx context.Context) (*Stream, error) { return c.accept(ctx, 1) }

func (c *Conn) accept(ctx context.Context, k int) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if q := c.acceptQueue[k]; len(q) > 0 {
			s := q[0]
			c.acceptQueue[k] = q[1:]
			return s, nil
		}
		if c.closeErr != nil {
			return nil, c.closeErr
		}
		ch := c.streamsChanged
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			c.mu.Lock()
			return nil, ctx.Err()
		}
		c.mu.Lock()
	}
}

// CloseWithError closes the connection with an application error code,
// waiting briefly until the CONNECTION_CLOSE frame has been sent.
func (c *Conn) CloseWithError(code uint64, reason string) error {
	c.mu.Lock()
	if !c.handshakeComplete && c.state == stateOpen {
		// Before the handshake completes an application close is sent as
		// a transport APPLICATION_ERROR (RFC 9000, section 10.2.3).
		c.closeLocal(&ApplicationError{Code: code, Reason: reason},
			&connectionCloseFrame{code: uint64(ApplicationErrorCode)})
	} else {
		c.closeLocal(&ApplicationError{Code: code, Reason: reason},
			&connectionCloseFrame{app: true, code: code, reason: reason})
	}
	ch := c.closeSentCh
	c.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(time.Second):
	}
	return nil
}

// Close closes the connection with application error code 0.
func (c *Conn) Close() error { return c.CloseWithError(0, "") }

// Done is closed when the connection has terminated.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns the reason the connection closed, or nil while it is open.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// ConnectionState returns information about the connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ConnectionState{TLS: c.tls.ConnectionState(), Version: version1, UsedRetry: c.gotRetry}
}

// Stats returns connection statistics.
func (c *Conn) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.SmoothedRTT = c.rtt.smoothed
	s.MinRTT = c.rtt.min
	s.CongestionWindow = c.cc.window
	return s
}

func (c *Conn) LocalAddr() net.Addr  { return c.pconn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) String() string {
	role := "server"
	if c.isClient {
		role = "client"
	}
	return fmt.Sprintf("quic %s %x->%v", role, c.scid, c.remote)
}
