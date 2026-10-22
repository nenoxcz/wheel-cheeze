package quic

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// Dial establishes a QUIC connection to addr ("host:port"). tlsConf must
// set NextProtos (ALPN is mandatory for QUIC); an empty ServerName is taken
// from addr. Dial returns once the handshake has completed.
func Dial(ctx context.Context, addr string, tlsConf *tls13.Config, conf *Config) (*Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tc := tlsConf.Clone()
	if tc.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		tc.ServerName = host
	}
	c, err := DialConn(ctx, pc, raddr, tc, conf)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return c, nil
}

// DialConn establishes a connection over an existing packet connection,
// which the returned Conn owns and closes.
func DialConn(ctx context.Context, pc net.PacketConn, raddr net.Addr, tlsConf *tls13.Config, conf *Config) (*Conn, error) {
	if len(tlsConf.NextProtos) == 0 {
		return nil, fmt.Errorf("quic: tls13.Config.NextProtos must be set")
	}
	if u, ok := pc.(*net.UDPConn); ok {
		u.SetReadBuffer(4 << 20)
		u.SetWriteBuffer(4 << 20)
	}
	c := newConn(true, conf, pc, raddr)
	c.odcid = randomCID()
	c.dcid = c.odcid
	c.initDCID = c.odcid
	sp := c.spaces[spaceInitial]
	sp.writeKeys, sp.readKeys = initialKeys(c.odcid, true)
	c.buildLocalParams()
	c.tls = tls13.QUICClient(tlsConf, c.localParams.marshal(false))

	c.mu.Lock()
	err := c.tls.Start()
	if err == nil {
		err = c.handleTLSEvents()
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c.logf("dialing %v, DCID %x SCID %x", raddr, c.dcid, c.scid)

	go c.readLoop()
	go c.run()

	select {
	case <-c.handshakeDoneCh:
		return c, nil
	case <-c.closingCh:
		// Return as soon as our CONNECTION_CLOSE (if any) is out; the
		// connection finishes closing in the background.
		select {
		case <-c.closeSentCh:
		case <-c.done:
		case <-time.After(time.Second):
		}
		return nil, c.Err()
	case <-ctx.Done():
		c.mu.Lock()
		c.closeLocal(ctx.Err(), &connectionCloseFrame{code: uint64(ApplicationErrorCode)})
		c.mu.Unlock()
		select {
		case <-c.closeSentCh:
		case <-time.After(100 * time.Millisecond):
		}
		return nil, fmt.Errorf("quic: dial: %w", ctx.Err())
	}
}

func (c *Conn) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := c.pconn.ReadFrom(buf)
		if err != nil {
			return
		}
		if addr.String() != c.remote.String() {
			continue
		}
		c.deliver(datagram{data: append([]byte(nil), buf[:n]...), t: time.Now()})
	}
}
