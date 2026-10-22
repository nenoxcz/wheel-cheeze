package quic

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/nenoxcz/wheel-cheeze/tls13"
)

const retryTokenLifetime = 10 * time.Second

// Listener accepts QUIC connections on a UDP socket.
type Listener struct {
	pc      net.PacketConn
	tlsConf *tls13.Config
	conf    *Config

	mu       sync.Mutex
	conns    map[string]*Conn // keyed by connection IDs that route to it
	acceptCh chan *Conn
	closed   chan struct{}
	once     sync.Once
	tokenKey []byte
}

// Listen creates a Listener on a UDP address such as ":4433".
func Listen(addr string, tlsConf *tls13.Config, conf *Config) (*Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	return NewListener(pc, tlsConf, conf)
}

// NewListener serves QUIC on an existing packet connection, which the
// Listener owns.
func NewListener(pc net.PacketConn, tlsConf *tls13.Config, conf *Config) (*Listener, error) {
	if len(tlsConf.Certificates) == 0 && tlsConf.GetCertificate == nil {
		return nil, errors.New("quic: server requires a certificate")
	}
	if len(tlsConf.NextProtos) == 0 {
		return nil, errors.New("quic: tls13.Config.NextProtos must be set")
	}
	if u, ok := pc.(*net.UDPConn); ok {
		u.SetReadBuffer(4 << 20)
		u.SetWriteBuffer(4 << 20)
	}
	l := &Listener{
		pc:       pc,
		tlsConf:  tlsConf,
		conf:     conf.withDefaults(),
		conns:    map[string]*Conn{},
		acceptCh: make(chan *Conn, 64),
		closed:   make(chan struct{}),
		tokenKey: make([]byte, 32),
	}
	rand.Read(l.tokenKey)
	go l.readLoop()
	return l, nil
}

// Addr returns the local address.
func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// Accept returns the next connection whose handshake has completed.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close closes all connections and the socket.
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.mu.Lock()
		seen := map[*Conn]bool{}
		var conns []*Conn
		for _, c := range l.conns {
			if !seen[c] {
				seen[c] = true
				conns = append(conns, c)
			}
		}
		l.mu.Unlock()
		var wg sync.WaitGroup
		for _, c := range conns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.CloseWithError(0, "server shutting down")
			}()
		}
		wg.Wait()
		l.pc.Close()
	})
	return nil
}

func (l *Listener) queueAccept(c *Conn) {
	select {
	case l.acceptCh <- c:
	default:
		c.closeLocal(transportErr(ConnectionRefused, "accept queue full"),
			&connectionCloseFrame{code: uint64(ConnectionRefused), reason: "server busy"})
	}
}

func (l *Listener) removeConn(c *Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.conns {
		if v == c {
			delete(l.conns, k)
		}
	}
}

func (l *Listener) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		l.handleDatagram(append([]byte(nil), buf[:n]...), addr)
	}
}

func (l *Listener) handleDatagram(data []byte, addr net.Addr) {
	dcid, ok := peekDCID(data)
	if !ok {
		return
	}
	l.mu.Lock()
	c := l.conns[string(dcid)]
	l.mu.Unlock()
	if c != nil {
		c.deliver(datagram{data: data, t: time.Now()})
		return
	}
	if data[0]&0x80 == 0 {
		return // short header packet for an unknown connection
	}
	hdr, err := parseLongHeader(data)
	if err != nil {
		return
	}
	if hdr.version != version1 {
		if hdr.version != 0 && len(data) >= minInitialDatagram {
			var rb [1]byte
			rand.Read(rb[:])
			l.pc.WriteTo(buildVersionNegotiation(hdr.dcid, hdr.scid, rb[0]), addr)
		}
		return
	}
	if hdr.typ != packetTypeInitial || len(data) < minInitialDatagram || len(hdr.dcid) < 8 {
		return
	}
	select {
	case <-l.closed:
		return
	default:
	}

	odcid := hdr.dcid
	var retrySCID []byte
	validated := false
	if l.conf.RequireAddressValidation {
		if len(hdr.token) == 0 {
			l.sendRetry(hdr, addr)
			return
		}
		odcid, ok = l.validateToken(hdr.token, addr, hdr.dcid)
		if !ok {
			return // invalid or expired token: drop (RFC 9000, 8.1.3)
		}
		retrySCID = hdr.dcid
		validated = true
	}

	c = newConn(false, l.conf, l.pc, addr)
	c.listener = l
	c.odcid = bytes.Clone(odcid)
	c.initDCID = bytes.Clone(hdr.dcid)
	c.dcid = bytes.Clone(hdr.scid)
	c.peerSCID = c.dcid
	c.addressValidated = validated
	if retrySCID != nil {
		c.gotRetry = true
		c.retrySCID = bytes.Clone(retrySCID)
	}
	sp := c.spaces[spaceInitial]
	sp.writeKeys, sp.readKeys = initialKeys(hdr.dcid, false)
	c.buildLocalParams()
	c.tls = tls13.QUICServer(l.tlsConf, c.localParams.marshal(true))
	if err := c.tls.Start(); err != nil {
		return
	}
	c.logf("new connection from %v, ODCID %x", addr, c.odcid)

	l.mu.Lock()
	l.conns[string(c.scid)] = c
	l.conns[string(c.initDCID)] = c
	l.mu.Unlock()
	go c.run()
	c.deliver(datagram{data: data, t: time.Now()})
}

// Retry tokens: timestamp || ODCID length || ODCID || HMAC(addr, retry SCID).

func (l *Listener) tokenMAC(body []byte, addr net.Addr, retrySCID []byte) []byte {
	m := hmac.New(sha256.New, l.tokenKey)
	m.Write(body)
	m.Write([]byte(addr.String()))
	m.Write(retrySCID)
	return m.Sum(nil)[:16]
}

func (l *Listener) sendRetry(hdr *longHeader, addr net.Addr) {
	newSCID := randomCID()
	body := binary.BigEndian.AppendUint64(nil, uint64(time.Now().UnixNano()))
	body = append(body, byte(len(hdr.dcid)))
	body = append(body, hdr.dcid...)
	token := append(body, l.tokenMAC(body, addr, newSCID)...)
	var rb [1]byte
	rand.Read(rb[:])
	l.pc.WriteTo(buildRetry(hdr.scid, newSCID, hdr.dcid, token, rb[0]), addr)
}

func (l *Listener) validateToken(token []byte, addr net.Addr, retrySCID []byte) ([]byte, bool) {
	if len(token) < 9+16 {
		return nil, false
	}
	n := int(token[8])
	if len(token) != 9+n+16 {
		return nil, false
	}
	body, mac := token[:9+n], token[9+n:]
	if !hmac.Equal(mac, l.tokenMAC(body, addr, retrySCID)) {
		return nil, false
	}
	issued := time.Unix(0, int64(binary.BigEndian.Uint64(body)))
	if time.Since(issued) > retryTokenLifetime {
		return nil, false
	}
	return body[9:], true
}
