package tls13

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Record content types (RFC 8446, section 5.1).
const (
	recordChangeCipherSpec uint8 = 20
	recordAlert            uint8 = 21
	recordHandshake        uint8 = 22
	recordApplicationData  uint8 = 23
)

const (
	recordHeaderLen  = 5
	maxPlaintext     = 1 << 14
	maxCiphertext    = maxPlaintext + 256
	maxHandshakeSize = 256 << 10
	alertLevelFatal  = 2
)

// RecordHeaderError is returned when the peer's bytes do not parse as a TLS
// record. Header holds the offending bytes, which often reveal what the peer
// actually speaks (for example "HTTP/" from a plaintext web server).
type RecordHeaderError struct {
	Msg    string
	Header [recordHeaderLen]byte
}

func (e *RecordHeaderError) Error() string { return "tls13: " + e.Msg }

// halfConn holds the record protection state for one direction.
type halfConn struct {
	sync.Mutex
	level  Level
	suite  *CipherSuite
	secret []byte
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
	epoch  int // incremented on every key change
}

func (h *halfConn) setSecret(level Level, suite *CipherSuite, secret []byte) {
	key, iv := suite.TrafficKey(secret)
	aead, err := suite.NewAEAD(key)
	if err != nil {
		panic("tls13: invalid traffic key: " + err.Error())
	}
	h.level, h.suite, h.secret, h.aead, h.iv, h.seq = level, suite, secret, aead, iv, 0
	h.epoch++
}

func (h *halfConn) nonce() []byte {
	n := make([]byte, aeadNonceLength)
	copy(n, h.iv)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], h.seq)
	for i := range seq {
		n[aeadNonceLength-8+i] ^= seq[i]
	}
	return n
}

// Conn is a TLS 1.3 connection over a reliable byte stream. It implements
// net.Conn; Read and Write may be called concurrently.
type Conn struct {
	conn     net.Conn
	isClient bool
	config   *Config

	handshakeMu   sync.Mutex
	handshakeErr  error
	handshakeDone atomic.Bool
	hs            handshaker

	in               halfConn
	rawBuf           []byte // bytes read from conn; rawBuf[rawStart:rawEnd] is unread
	rawStart, rawEnd int
	hsBuf            []byte // incoming handshake bytes not yet forming a message
	appData          []byte // decrypted application data not yet returned by Read
	readErr          error  // sticky read-side error

	out             halfConn
	pendingHS       []byte // outgoing handshake bytes not yet framed
	outBuf          []byte // framed records not yet written
	sentFirstRecord bool
	writeErr        error
	closeNotifySent bool
}

// Client returns a client-side TLS 1.3 connection over conn.
func Client(conn net.Conn, config *Config) *Conn {
	return &Conn{conn: conn, isClient: true, config: config}
}

// Server returns a server-side TLS 1.3 connection over conn.
func Server(conn net.Conn, config *Config) *Conn {
	return &Conn{conn: conn, config: config}
}

// handshakeIO implementation for the record layer.

func (c *Conn) writeMessage(level Level, msg []byte) {
	if level != c.out.level {
		panic(fmt.Sprintf("tls13: handshake message at level %v but write level is %v", level, c.out.level))
	}
	c.pendingHS = append(c.pendingHS, msg...)
}

func (c *Conn) setReadSecret(level Level, suite *CipherSuite, secret []byte) {
	c.in.setSecret(level, suite, secret)
}

func (c *Conn) setWriteSecret(level Level, suite *CipherSuite, secret []byte) {
	c.framePendingHS()
	c.out.setSecret(level, suite, secret)
}

func (c *Conn) sendChangeCipherSpec() {
	c.framePendingHS()
	c.outBuf = append(c.outBuf, recordChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01)
}

// Record writing. The caller holds c.out.

func (c *Conn) framePendingHS() {
	for len(c.pendingHS) > 0 {
		n := min(len(c.pendingHS), maxPlaintext)
		c.appendRecord(recordHandshake, c.pendingHS[:n])
		c.pendingHS = c.pendingHS[n:]
	}
	c.pendingHS = nil
}

func (c *Conn) appendRecord(typ uint8, data []byte) {
	if c.out.aead == nil {
		version := versionTLS12
		if !c.sentFirstRecord && c.isClient && typ == recordHandshake {
			version = 0x0301 // see RFC 8446, section 5.1
		}
		c.sentFirstRecord = true
		c.outBuf = append(c.outBuf, typ, byte(version>>8), byte(version), byte(len(data)>>8), byte(len(data)))
		c.outBuf = append(c.outBuf, data...)
		return
	}
	c.sentFirstRecord = true
	n := len(data) + 1 + c.out.aead.Overhead()
	hdr := []byte{recordApplicationData, 0x03, 0x03, byte(n >> 8), byte(n)}
	inner := make([]byte, 0, len(data)+1+c.out.aead.Overhead())
	inner = append(inner, data...)
	inner = append(inner, typ)
	c.outBuf = append(c.outBuf, hdr...)
	c.outBuf = c.out.aead.Seal(c.outBuf, c.out.nonce(), inner, hdr)
	c.out.seq++
}

func (c *Conn) flushLocked() error {
	c.framePendingHS()
	if len(c.outBuf) == 0 {
		return nil
	}
	_, err := c.conn.Write(c.outBuf)
	c.outBuf = c.outBuf[:0]
	if err != nil {
		c.writeErr = err
	}
	return err
}

// sendAlertLocked sends a fatal alert (or close_notify). The caller holds
// c.out.
func (c *Conn) sendAlertLocked(a Alert) error {
	level := byte(alertLevelFatal)
	if a == AlertCloseNotify || a == AlertUserCanceled {
		level = 1
	}
	c.framePendingHS()
	c.appendRecord(recordAlert, []byte{level, byte(a)})
	err := c.flushLocked()
	if a == AlertCloseNotify {
		c.closeNotifySent = true
	} else if c.writeErr == nil {
		c.writeErr = &AlertError{Alert: a, Err: errors.New("connection aborted after sending an alert")}
	}
	return err
}

// Record reading. The caller holds c.in.

// fill ensures at least n unread bytes are buffered in rawBuf. Data handed
// out from the buffer stays valid until the next fill.
func (c *Conn) fill(n int) error {
	for c.rawEnd-c.rawStart < n {
		if len(c.rawBuf)-c.rawStart < n || len(c.rawBuf) == c.rawEnd {
			// Compact, growing the buffer if a single record needs it.
			size := max(len(c.rawBuf), recordHeaderLen+maxCiphertext, n)
			buf := c.rawBuf
			if len(buf) < size {
				buf = make([]byte, size)
			}
			c.rawEnd = copy(buf, c.rawBuf[c.rawStart:c.rawEnd])
			c.rawStart = 0
			c.rawBuf = buf
		}
		m, err := c.conn.Read(c.rawBuf[c.rawEnd:])
		c.rawEnd += m
		if c.rawEnd-c.rawStart >= n {
			return nil
		}
		if err != nil {
			if err == io.EOF && c.rawEnd > c.rawStart {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func isTemporary(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readRecord returns the next record's content type and plaintext.
func (c *Conn) readRecord() (uint8, []byte, error) {
	if err := c.fill(recordHeaderLen); err != nil {
		return 0, nil, err
	}
	var hdr [recordHeaderLen]byte
	copy(hdr[:], c.rawBuf[c.rawStart:])
	typ := hdr[0]
	n := int(hdr[3])<<8 | int(hdr[4])
	if typ < recordChangeCipherSpec || typ > recordApplicationData || hdr[1] != 0x03 {
		msg := "record header has an invalid content type or version"
		if !c.handshakeDone.Load() && c.in.aead == nil {
			msg = "first record does not look like a TLS handshake"
		}
		return 0, nil, &RecordHeaderError{Msg: msg, Header: hdr}
	}
	if n > maxCiphertext || (c.in.aead == nil && n > maxPlaintext) {
		return 0, nil, alertf(AlertRecordOverflow, "record of %d bytes exceeds the limit", n)
	}
	if err := c.fill(recordHeaderLen + n); err != nil {
		return 0, nil, err
	}
	payload := c.rawBuf[c.rawStart+recordHeaderLen : c.rawStart+recordHeaderLen+n]
	c.rawStart += recordHeaderLen + n

	if c.in.aead == nil || typ == recordChangeCipherSpec {
		if typ == recordApplicationData {
			return 0, nil, alertf(AlertUnexpectedMessage, "unencrypted application data")
		}
		return typ, append([]byte(nil), payload...), nil
	}
	if typ != recordApplicationData {
		return 0, nil, alertf(AlertUnexpectedMessage, "unencrypted record of type %d after keys were established", typ)
	}
	plain, err := c.in.aead.Open(nil, c.in.nonce(), payload, hdr[:])
	if err != nil {
		return 0, nil, alertf(AlertBadRecordMAC, "record decryption failed")
	}
	c.in.seq++
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, alertf(AlertUnexpectedMessage, "record has no content type")
	}
	typ, plain = plain[i], plain[:i]
	if len(plain) > maxPlaintext {
		return 0, nil, alertf(AlertRecordOverflow, "decrypted record too large")
	}
	return typ, plain, nil
}

// processRecord handles a record of a non-application type. Handshake
// messages are dispatched to handle.
func (c *Conn) processRecord(typ uint8, data []byte, handle func(level Level, msg []byte) error) error {
	switch typ {
	case recordChangeCipherSpec:
		if len(data) != 1 || data[0] != 1 || c.handshakeDone.Load() {
			return alertf(AlertUnexpectedMessage, "unexpected change_cipher_spec record")
		}
		return nil // dropped (RFC 8446, section 5)
	case recordAlert:
		if len(data) != 2 {
			return alertf(AlertDecodeError, "malformed alert record")
		}
		a := Alert(data[1])
		switch a {
		case AlertCloseNotify:
			return io.EOF
		case AlertUserCanceled:
			return nil
		}
		return &AlertError{Alert: a, Remote: true}
	case recordHandshake:
		if len(data) == 0 {
			return alertf(AlertUnexpectedMessage, "zero-length handshake record")
		}
		c.hsBuf = append(c.hsBuf, data...)
		for len(c.hsBuf) >= 4 {
			n := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
			if n > maxHandshakeSize {
				return alertf(AlertDecodeError, "handshake message of %d bytes is too large", n)
			}
			if len(c.hsBuf) < 4+n {
				break
			}
			msg := append([]byte(nil), c.hsBuf[:4+n]...)
			c.hsBuf = c.hsBuf[4+n:]
			epoch := c.in.epoch
			if err := handle(c.in.level, msg); err != nil {
				return err
			}
			if c.in.epoch != epoch && len(c.hsBuf) > 0 {
				return alertf(AlertUnexpectedMessage, "handshake data spans a key change")
			}
		}
		if len(c.hsBuf) == 0 {
			c.hsBuf = nil
		}
		return nil
	case recordApplicationData:
		return alertf(AlertUnexpectedMessage, "application data before the handshake completed")
	}
	return alertf(AlertUnexpectedMessage, "unknown record type %d", typ)
}

// Handshake runs the handshake if it has not run yet.
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the handshake, aborting it by closing the underlying
// connection if ctx is done first.
func (c *Conn) HandshakeContext(ctx context.Context) (err error) {
	if c.handshakeDone.Load() {
		return nil
	}
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if c.handshakeDone.Load() {
		return nil
	}

	if ctx.Done() != nil {
		stop := make(chan struct{})
		interrupted := make(chan bool, 1)
		go func() {
			select {
			case <-ctx.Done():
				c.conn.Close()
				interrupted <- true
			case <-stop:
				interrupted <- false
			}
		}()
		defer func() {
			close(stop)
			if <-interrupted && err != nil {
				err = fmt.Errorf("tls13: handshake aborted: %w", ctx.Err())
				c.handshakeErr = err
			}
		}()
	}

	c.in.Lock()
	defer c.in.Unlock()
	c.out.Lock()
	defer c.out.Unlock()

	err = c.runHandshake()
	if err != nil {
		var ae *AlertError
		if errors.As(err, &ae) && !ae.Remote && c.writeErr == nil {
			c.sendAlertLocked(ae.Alert)
		}
		if err == io.EOF {
			err = errors.New("tls13: connection closed by peer during handshake")
		}
		c.handshakeErr = err
		c.readErr = err
		return err
	}
	c.handshakeDone.Store(true)
	return nil
}

func (c *Conn) runHandshake() error {
	if c.config == nil {
		c.config = &Config{}
	}
	if c.isClient {
		c.hs = newClientHandshake(c.config, c, false, nil)
	} else {
		c.hs = newServerHandshake(c.config, c, false, nil)
	}
	if err := c.hs.start(); err != nil {
		return err
	}
	if err := c.flushLocked(); err != nil {
		return err
	}
	for !c.hs.complete() {
		typ, data, err := c.readRecord()
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if err := c.processRecord(typ, data, c.hs.handleMessage); err != nil {
			return err
		}
		if err := c.flushLocked(); err != nil {
			return err
		}
	}
	return nil
}

// handlePostHandshake processes NewSessionTicket and KeyUpdate. The caller
// holds c.in.
func (c *Conn) handlePostHandshake(level Level, msg []byte) error {
	switch msg[0] {
	case typeNewSessionTicket:
		if !c.isClient {
			return alertf(AlertUnexpectedMessage, "client sent NewSessionTicket")
		}
		// Resumption is not implemented; the ticket is validated and dropped.
		_, err := parseNewSessionTicket(msg)
		return err
	case typeKeyUpdate:
		requestUpdate, err := parseKeyUpdate(msg)
		if err != nil {
			return err
		}
		c.in.setSecret(LevelApplication, c.in.suite, c.in.suite.NextTrafficSecret(c.in.secret))
		if requestUpdate {
			c.out.Lock()
			defer c.out.Unlock()
			if c.writeErr != nil {
				return nil
			}
			return c.updateWriteKeyLocked(false)
		}
		return nil
	}
	return unexpected(msg[0], "application data")
}

func (c *Conn) updateWriteKeyLocked(requestPeer bool) error {
	c.appendRecord(recordHandshake, marshalKeyUpdate(requestPeer))
	c.out.setSecret(LevelApplication, c.out.suite, c.out.suite.NextTrafficSecret(c.out.secret))
	return c.flushLocked()
}

// UpdateKeys sends a KeyUpdate message and switches to the next write
// traffic secret. If requestPeer is set the peer is asked to update too.
func (c *Conn) UpdateKeys(requestPeer bool) error {
	if err := c.Handshake(); err != nil {
		return err
	}
	c.out.Lock()
	defer c.out.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	return c.updateWriteKeyLocked(requestPeer)
}

// Read reads application data, running the handshake first if needed.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.in.Lock()
	defer c.in.Unlock()
	for len(c.appData) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		typ, data, err := c.readRecord()
		if err == nil {
			if typ == recordApplicationData {
				c.appData = data
				continue
			}
			err = c.processRecord(typ, data, c.handlePostHandshake)
		}
		if err != nil {
			if isTemporary(err) {
				return 0, err
			}
			var ae *AlertError
			if errors.As(err, &ae) && !ae.Remote {
				c.out.Lock()
				if c.writeErr == nil {
					c.sendAlertLocked(ae.Alert)
				}
				c.out.Unlock()
			}
			c.readErr = err
		}
	}
	n := copy(b, c.appData)
	c.appData = c.appData[n:]
	return n, nil
}

// Write sends application data, running the handshake first if needed.
func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.out.Lock()
	defer c.out.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.closeNotifySent {
		return 0, errors.New("tls13: write after CloseWrite")
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), maxPlaintext)
		c.appendRecord(recordApplicationData, b[:n])
		if err := c.flushLocked(); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// CloseWrite sends close_notify, signalling that no more data will be
// written. Reading remains possible.
func (c *Conn) CloseWrite() error {
	if !c.handshakeDone.Load() {
		return errors.New("tls13: CloseWrite before the handshake completed")
	}
	c.out.Lock()
	defer c.out.Unlock()
	if c.closeNotifySent || c.writeErr != nil {
		return nil
	}
	return c.sendAlertLocked(AlertCloseNotify)
}

// Close sends close_notify (if the handshake completed) and closes the
// underlying connection.
func (c *Conn) Close() error {
	if c.handshakeDone.Load() {
		// Bound the time spent on close_notify if the peer stops reading.
		c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		c.CloseWrite()
	}
	return c.conn.Close()
}

// ConnectionState returns details about the connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.hs == nil {
		return ConnectionState{}
	}
	return c.hs.state()
}

// ExportKeyingMaterial derives keying material (RFC 8446, section 7.5).
func (c *Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if !c.handshakeDone.Load() {
		return nil, errors.New("tls13: handshake not complete")
	}
	suite, secret := c.hs.exporterSecret()
	return suite.exportKeyingMaterial(secret, label, context, length), nil
}

func (c *Conn) NetConn() net.Conn                  { return c.conn }
func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// DialContext connects to addr and performs a TLS 1.3 client handshake. If
// config.ServerName is empty it is taken from addr.
func DialContext(ctx context.Context, network, addr string, config *Config) (*Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := config.Clone()
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg.ServerName = host
	}
	conn := Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Dial is DialContext with a background context.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, config)
}

type listener struct {
	net.Listener
	config *Config
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// NewListener wraps inner so that accepted connections are TLS 1.3 servers.
// The handshake runs on first Read or Write, or an explicit Handshake call.
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{inner, config}
}

// Listen creates a TLS 1.3 listener on the given address.
func Listen(network, addr string, config *Config) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}
