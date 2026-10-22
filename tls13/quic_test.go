package tls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"testing"
)

// quicSide abstracts our QUICConn and crypto/tls's so they can be wired
// together in memory.
type quicSide interface {
	start() error
	handle(level Level, data []byte) error
	// drain returns the queued events in a normalized form.
	drain() []QUICEvent
	alpn() string
}

type ourSide struct{ q *QUICConn }

func (s *ourSide) start() error                          { return s.q.Start() }
func (s *ourSide) handle(level Level, data []byte) error { return s.q.HandleData(level, data) }
func (s *ourSide) alpn() string                          { return s.q.ConnectionState().NegotiatedProtocol }
func (s *ourSide) drain() []QUICEvent {
	var out []QUICEvent
	for {
		e := s.q.NextEvent()
		if e.Kind == QUICNoEvent {
			return out
		}
		out = append(out, e)
	}
}

type stdSide struct {
	q      *tls.QUICConn
	params []byte
	server bool
}

func (s *stdSide) start() error {
	if !s.server {
		s.q.SetTransportParameters(s.params)
	}
	return s.q.Start(context.Background())
}
func (s *stdSide) handle(level Level, data []byte) error {
	return s.q.HandleData(tls.QUICEncryptionLevel(level), data)
}
func (s *stdSide) alpn() string { return s.q.ConnectionState().NegotiatedProtocol }
func (s *stdSide) drain() []QUICEvent {
	var out []QUICEvent
	for {
		e := s.q.NextEvent()
		switch e.Kind {
		case tls.QUICNoEvent:
			return out
		case tls.QUICTransportParametersRequired:
			s.q.SetTransportParameters(s.params)
		case tls.QUICSetReadSecret:
			out = append(out, QUICEvent{Kind: QUICSetReadSecret, Level: Level(e.Level), Suite: CipherSuiteByID(e.Suite), Secret: bytes.Clone(e.Data)})
		case tls.QUICSetWriteSecret:
			out = append(out, QUICEvent{Kind: QUICSetWriteSecret, Level: Level(e.Level), Suite: CipherSuiteByID(e.Suite), Secret: bytes.Clone(e.Data)})
		case tls.QUICWriteData:
			out = append(out, QUICEvent{Kind: QUICWriteData, Level: Level(e.Level), Data: bytes.Clone(e.Data)})
		case tls.QUICTransportParameters:
			out = append(out, QUICEvent{Kind: QUICTransportParameters, Data: bytes.Clone(e.Data)})
		case tls.QUICHandshakeDone:
			out = append(out, QUICEvent{Kind: QUICHandshakeDone})
		}
	}
}

type sideState struct {
	readSecrets  map[Level][]byte
	writeSecrets map[Level][]byte
	peerParams   []byte
	done         bool
}

// runQUICHandshake shuttles CRYPTO data between client and server until
// both are done or one fails. Data is delivered in small fragments to
// exercise message reassembly.
func runQUICHandshake(t *testing.T, client, server quicSide) (cs, ss *sideState, err error) {
	t.Helper()
	cs = &sideState{readSecrets: map[Level][]byte{}, writeSecrets: map[Level][]byte{}}
	ss = &sideState{readSecrets: map[Level][]byte{}, writeSecrets: map[Level][]byte{}}
	if err := server.start(); err != nil {
		return cs, ss, fmt.Errorf("server start: %w", err)
	}
	if err := client.start(); err != nil {
		return cs, ss, fmt.Errorf("client start: %w", err)
	}
	type pending struct {
		level Level
		data  []byte
	}
	process := func(from quicSide, st *sideState) []pending {
		var out []pending
		for _, e := range from.drain() {
			switch e.Kind {
			case QUICWriteData:
				out = append(out, pending{e.Level, e.Data})
			case QUICSetReadSecret:
				st.readSecrets[e.Level] = e.Secret
			case QUICSetWriteSecret:
				st.writeSecrets[e.Level] = e.Secret
			case QUICTransportParameters:
				st.peerParams = e.Data
			case QUICHandshakeDone:
				st.done = true
			}
		}
		return out
	}
	deliver := func(to quicSide, msgs []pending) error {
		for _, m := range msgs {
			for off := 0; off < len(m.data); off += 300 {
				end := min(off+300, len(m.data))
				if err := to.handle(m.level, m.data[off:end]); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for i := 0; i < 10 && !(cs.done && ss.done); i++ {
		if err := deliver(server, process(client, cs)); err != nil {
			return cs, ss, fmt.Errorf("server: %w", err)
		}
		if err := deliver(client, process(server, ss)); err != nil {
			return cs, ss, fmt.Errorf("client: %w", err)
		}
	}
	process(client, cs)
	process(server, ss)
	if !cs.done || !ss.done {
		return cs, ss, errors.New("handshake did not complete")
	}
	return cs, ss, nil
}

func checkSecrets(t *testing.T, cs, ss *sideState) {
	t.Helper()
	for _, l := range []Level{LevelHandshake, LevelApplication} {
		if cs.writeSecrets[l] == nil || !bytes.Equal(cs.writeSecrets[l], ss.readSecrets[l]) {
			t.Errorf("%v client write secret does not match server read secret", l)
		}
		if ss.writeSecrets[l] == nil || !bytes.Equal(ss.writeSecrets[l], cs.readSecrets[l]) {
			t.Errorf("%v server write secret does not match client read secret", l)
		}
	}
}

var (
	clientTP = []byte("client transport parameters")
	serverTP = []byte("server transport parameters")
)

func TestQUICOurClientStdServer(t *testing.T) {
	for _, groups := range [][]CurveID{nil, {CurveP384}} {
		scfg := &tls.Config{
			Certificates: []tls.Certificate{toStdCert(leafCert(t, "p256"))},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS13,
		}
		if groups != nil {
			// Force a HelloRetryRequest; the stdlib only supports the
			// classical group here.
			scfg.CurvePreferences = []tls.CurveID{tls.CurveP384}
		}
		cfg := ourClientConfig(t)
		cfg.NextProtos = []string{"h3"}
		client := &ourSide{QUICClient(cfg, clientTP)}
		server := &stdSide{q: tls.QUICServer(&tls.QUICConfig{TLSConfig: scfg}), params: serverTP, server: true}
		cs, ss, err := runQUICHandshake(t, client, server)
		if err != nil {
			t.Fatal(err)
		}
		checkSecrets(t, cs, ss)
		if !bytes.Equal(cs.peerParams, serverTP) || !bytes.Equal(ss.peerParams, clientTP) {
			t.Fatalf("transport parameters not exchanged")
		}
		if client.alpn() != "h3" {
			t.Fatalf("ALPN = %q", client.alpn())
		}
		if groups != nil && !client.q.ConnectionState().DidHelloRetryRequest {
			t.Fatalf("expected HelloRetryRequest")
		}

		// A post-handshake NewSessionTicket at the application level must
		// be accepted and ignored.
		if err := server.q.SendSessionTicket(tls.QUICSessionTicketOptions{}); err != nil {
			t.Fatal(err)
		}
		for _, e := range server.drain() {
			if e.Kind == QUICWriteData {
				if e.Level != LevelApplication {
					t.Fatalf("ticket at %v", e.Level)
				}
				if err := client.handle(e.Level, e.Data); err != nil {
					t.Fatalf("handling NewSessionTicket: %v", err)
				}
			}
		}
	}
}

func TestQUICStdClientOurServer(t *testing.T) {
	ccfg := &tls.Config{ServerName: "example.test", RootCAs: getPKI(t).pool, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	client := &stdSide{q: tls.QUICClient(&tls.QUICConfig{TLSConfig: ccfg}), params: clientTP}
	server := &ourSide{QUICServer(&Config{
		Certificates: []Certificate{leafCert(t, "ed25519")},
		NextProtos:   []string{"h3"},
	}, serverTP)}
	cs, ss, err := runQUICHandshake(t, client, server)
	if err != nil {
		t.Fatal(err)
	}
	checkSecrets(t, cs, ss)
	if !bytes.Equal(cs.peerParams, serverTP) || !bytes.Equal(ss.peerParams, clientTP) {
		t.Fatalf("transport parameters not exchanged")
	}
	if st := server.q.ConnectionState(); st.CurveID != X25519MLKEM768 || st.NegotiatedProtocol != "h3" {
		t.Fatalf("server state %+v", st)
	}
}

func TestQUICOurselves(t *testing.T) {
	cfg := ourClientConfig(t)
	cfg.NextProtos = []string{"h3"}
	client := &ourSide{QUICClient(cfg, clientTP)}
	server := &ourSide{QUICServer(&Config{
		Certificates:     []Certificate{leafCert(t, "rsa")},
		NextProtos:       []string{"h3"},
		CurvePreferences: []CurveID{CurveP256},
		ClientAuth:       RequestClientCert,
	}, serverTP)}
	cs, ss, err := runQUICHandshake(t, client, server)
	if err != nil {
		t.Fatal(err)
	}
	checkSecrets(t, cs, ss)
}

func TestQUICRequiresALPN(t *testing.T) {
	cfg := ourClientConfig(t)
	cfg.NextProtos = nil
	client := &ourSide{QUICClient(cfg, clientTP)}
	server := &ourSide{QUICServer(&Config{Certificates: []Certificate{leafCert(t, "p256")}, NextProtos: []string{"h3"}}, serverTP)}
	_, _, err := runQUICHandshake(t, client, server)
	var ae *AlertError
	if !errors.As(err, &ae) || ae.Alert != AlertNoApplicationProtocol {
		t.Fatalf("got %v", err)
	}
	if AlertCode(err) != AlertNoApplicationProtocol {
		t.Fatalf("AlertCode = %v", AlertCode(err))
	}
}
