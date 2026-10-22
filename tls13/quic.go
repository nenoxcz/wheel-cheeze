package tls13

import (
	"errors"
	"fmt"
)

// QUICEventKind identifies what a QUICEvent asks the QUIC layer to do.
type QUICEventKind int

const (
	// QUICNoEvent means the event queue is empty.
	QUICNoEvent QUICEventKind = iota
	// QUICSetReadSecret and QUICSetWriteSecret install packet protection
	// keys for Level, derived from Secret with Suite.
	QUICSetReadSecret
	QUICSetWriteSecret
	// QUICWriteData carries handshake bytes to send in CRYPTO frames at
	// Level.
	QUICWriteData
	// QUICTransportParameters carries the peer's raw transport parameters
	// in Data.
	QUICTransportParameters
	// QUICHandshakeDone reports that the TLS handshake has completed.
	QUICHandshakeDone
)

// QUICEvent is produced by QUICConn for the QUIC transport to act upon.
type QUICEvent struct {
	Kind   QUICEventKind
	Level  Level
	Data   []byte
	Suite  *CipherSuite
	Secret []byte
}

// QUICConn runs a TLS 1.3 handshake on behalf of a QUIC connection
// (RFC 9001). It never touches the network: handshake bytes are passed in
// with HandleData and come out as QUICWriteData events, and keys are
// exported as secrets. It is not safe for concurrent use.
type QUICConn struct {
	hs        handshaker
	events    []QUICEvent
	next      int
	inBuf     [4][]byte // partial incoming messages per level
	err       error
	started   bool
	sentTP    bool
	sentDone  bool
	readLevel Level
}

// QUICClient returns a client-side handshake that sends transportParams in
// the quic_transport_parameters extension.
func QUICClient(config *Config, transportParams []byte) *QUICConn {
	q := &QUICConn{}
	q.hs = newClientHandshake(config, q, true, transportParams)
	return q
}

// QUICServer returns a server-side handshake.
func QUICServer(config *Config, transportParams []byte) *QUICConn {
	q := &QUICConn{}
	q.hs = newServerHandshake(config, q, true, transportParams)
	return q
}

func (q *QUICConn) writeMessage(level Level, msg []byte) {
	if n := len(q.events); n > q.next && q.events[n-1].Kind == QUICWriteData && q.events[n-1].Level == level {
		q.events[n-1].Data = append(q.events[n-1].Data, msg...)
		return
	}
	q.events = append(q.events, QUICEvent{Kind: QUICWriteData, Level: level, Data: append([]byte(nil), msg...)})
}

func (q *QUICConn) setReadSecret(level Level, suite *CipherSuite, secret []byte) {
	q.readLevel = level
	q.events = append(q.events, QUICEvent{Kind: QUICSetReadSecret, Level: level, Suite: suite, Secret: secret})
}

func (q *QUICConn) setWriteSecret(level Level, suite *CipherSuite, secret []byte) {
	q.events = append(q.events, QUICEvent{Kind: QUICSetWriteSecret, Level: level, Suite: suite, Secret: secret})
}

func (q *QUICConn) sendChangeCipherSpec() {}

// Start begins the handshake. For a client this produces the ClientHello.
func (q *QUICConn) Start() error {
	if q.started {
		return errors.New("tls13: QUICConn already started")
	}
	q.started = true
	if err := q.hs.start(); err != nil {
		q.err = err
		return err
	}
	return nil
}

// HandleData passes handshake bytes received in CRYPTO frames at level, in
// order. The bytes need not align with message boundaries.
func (q *QUICConn) HandleData(level Level, data []byte) error {
	if q.err != nil {
		return q.err
	}
	if !q.started {
		return errors.New("tls13: HandleData before Start")
	}
	if level > LevelApplication {
		return errors.New("tls13: invalid encryption level")
	}
	q.inBuf[level] = append(q.inBuf[level], data...)
	for {
		buf := q.inBuf[level]
		if len(buf) < 4 {
			break
		}
		n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if n > maxHandshakeSize {
			return q.fail(alertf(AlertDecodeError, "handshake message of %d bytes is too large", n))
		}
		if len(buf) < 4+n {
			break
		}
		msg := append([]byte(nil), buf[:4+n]...)
		q.inBuf[level] = buf[4+n:]

		var err error
		if q.hs.complete() {
			err = q.handlePostHandshake(level, msg)
		} else {
			if level != q.readLevel {
				err = alertf(AlertUnexpectedMessage, "handshake message at %v while expecting %v", level, q.readLevel)
			} else {
				before := q.readLevel
				err = q.hs.handleMessage(level, msg)
				if err == nil && q.readLevel != before && len(q.inBuf[level]) > 0 {
					err = alertf(AlertUnexpectedMessage, "handshake data at %v continues past a key change", level)
				}
			}
		}
		if err != nil {
			return q.fail(err)
		}
		q.queueStatusEvents()
	}
	if len(q.inBuf[level]) == 0 {
		q.inBuf[level] = nil
	}
	return nil
}

func (q *QUICConn) queueStatusEvents() {
	if !q.sentTP && q.hs.peerQUICParams() != nil {
		q.sentTP = true
		q.events = append(q.events, QUICEvent{Kind: QUICTransportParameters, Data: q.hs.peerQUICParams()})
	}
	if !q.sentDone && q.hs.complete() {
		q.sentDone = true
		q.events = append(q.events, QUICEvent{Kind: QUICHandshakeDone})
	}
}

func (q *QUICConn) handlePostHandshake(level Level, msg []byte) error {
	if level != LevelApplication {
		return alertf(AlertUnexpectedMessage, "handshake message at %v after the handshake completed", level)
	}
	switch msg[0] {
	case typeNewSessionTicket:
		if _, ok := q.hs.(*clientHandshake); !ok {
			return alertf(AlertUnexpectedMessage, "client sent NewSessionTicket")
		}
		_, err := parseNewSessionTicket(msg)
		return err
	case typeKeyUpdate:
		// QUIC has its own key update mechanism (RFC 9001, section 6).
		return alertf(AlertUnexpectedMessage, "KeyUpdate is not allowed over QUIC")
	}
	return unexpected(msg[0], "nothing")
}

func (q *QUICConn) fail(err error) error {
	q.err = err
	return err
}

// NextEvent returns the next pending event, or one of kind QUICNoEvent.
func (q *QUICConn) NextEvent() QUICEvent {
	if q.next >= len(q.events) {
		q.events, q.next = q.events[:0], 0
		return QUICEvent{}
	}
	e := q.events[q.next]
	q.events[q.next] = QUICEvent{}
	q.next++
	return e
}

// ConnectionState returns details about the handshake.
func (q *QUICConn) ConnectionState() ConnectionState { return q.hs.state() }

// AlertCode returns the alert carried by err, for use in a QUIC
// CRYPTO_ERROR (0x0100 + alert).
func AlertCode(err error) Alert { return alertFor(err) }

// String helps when logging events.
func (e QUICEvent) String() string {
	switch e.Kind {
	case QUICSetReadSecret:
		return fmt.Sprintf("SetReadSecret(%v, %s)", e.Level, e.Suite.Name)
	case QUICSetWriteSecret:
		return fmt.Sprintf("SetWriteSecret(%v, %s)", e.Level, e.Suite.Name)
	case QUICWriteData:
		return fmt.Sprintf("WriteData(%v, %d bytes)", e.Level, len(e.Data))
	case QUICTransportParameters:
		return fmt.Sprintf("TransportParameters(%d bytes)", len(e.Data))
	case QUICHandshakeDone:
		return "HandshakeDone"
	}
	return "NoEvent"
}
