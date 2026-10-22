package tls13

import (
	"crypto/hmac"
	"crypto/x509"
	"hash"
	"slices"
)

// Level is an encryption level. Over TCP the levels follow each other on a
// single record stream; QUIC carries each level in its own packet number
// space (RFC 9001, section 4).
type Level uint8

const (
	LevelInitial Level = iota
	LevelEarly
	LevelHandshake
	LevelApplication
)

func (l Level) String() string {
	switch l {
	case LevelInitial:
		return "Initial"
	case LevelEarly:
		return "0-RTT"
	case LevelHandshake:
		return "Handshake"
	case LevelApplication:
		return "1-RTT"
	}
	return "unknown"
}

// handshakeIO is what the handshake state machines need from the transport
// (the TLS record layer, or QUIC CRYPTO frames).
type handshakeIO interface {
	// writeMessage queues a handshake message at the given level.
	writeMessage(level Level, msg []byte)
	// setReadSecret and setWriteSecret install traffic secrets.
	setReadSecret(level Level, suite *CipherSuite, secret []byte)
	setWriteSecret(level Level, suite *CipherSuite, secret []byte)
	// sendChangeCipherSpec emits a middlebox-compatibility CCS record. It
	// is a no-op for QUIC.
	sendChangeCipherSpec()
}

// handshaker is a TLS 1.3 handshake state machine for one side.
type handshaker interface {
	// start emits the first flight (client only; a no-op for servers).
	start() error
	// handleMessage processes one complete handshake message received at
	// the given level.
	handleMessage(level Level, msg []byte) error
	// complete reports whether the handshake has finished.
	complete() bool
	state() ConnectionState
	exporterSecret() (*CipherSuite, []byte)
	peerQUICParams() []byte
}

// transcript accumulates handshake messages before the hash is known and
// hashes them afterwards.
type transcript struct {
	buffered [][]byte
	h        hash.Hash
}

func (t *transcript) write(msg []byte) {
	if t.h != nil {
		t.h.Write(msg)
		return
	}
	t.buffered = append(t.buffered, msg)
}

func (t *transcript) setHash(h hash.Hash) {
	t.h = h
	for _, m := range t.buffered {
		h.Write(m)
	}
	t.buffered = nil
}

// restartForHRR replaces ClientHello1 with the synthetic message_hash
// message (RFC 8446, section 4.4.1). It must be called after setHash with
// ClientHello1 as the only message absorbed so far.
func (t *transcript) restartForHRR(newHash func() hash.Hash) {
	ch1Hash := t.h.Sum(nil)
	t.h = newHash()
	t.h.Write([]byte{typeMessageHash, 0, 0, byte(len(ch1Hash))})
	t.h.Write(ch1Hash)
}

func (t *transcript) sum() []byte { return t.h.Sum(nil) }

// common holds state shared by the client and server state machines.
type common struct {
	config *Config
	io     handshakeIO
	isQUIC bool
	// localQUICParams are our QUIC transport parameters.
	localQUICParams []byte

	suite      *CipherSuite
	ks         keySchedule
	transcript transcript

	clientRandom []byte
	done         bool

	// Negotiated results.
	group          CurveID
	alpn           string
	serverName     string
	peerScheme     SignatureScheme
	peerCerts      []*x509.Certificate
	verifiedChains [][]*x509.Certificate
	didHRR         bool
	peerParams     []byte
}

func (c *common) complete() bool { return c.done }

func (c *common) state() ConnectionState {
	cs := ConnectionState{
		HandshakeComplete:    c.done,
		CurveID:              c.group,
		SignatureScheme:      c.peerScheme,
		NegotiatedProtocol:   c.alpn,
		ServerName:           c.serverName,
		DidHelloRetryRequest: c.didHRR,
		PeerCertificates:     c.peerCerts,
		VerifiedChains:       c.verifiedChains,
	}
	if c.suite != nil {
		cs.Version = versionTLS13
		cs.CipherSuite = c.suite.ID
	}
	return cs
}

func (c *common) exporterSecret() (*CipherSuite, []byte) {
	return c.suite, c.ks.exporterSecret
}

func (c *common) peerQUICParams() []byte { return c.peerParams }

// send queues a marshalled message and adds it to the transcript.
func (c *common) send(level Level, msg []byte) {
	c.transcript.write(msg)
	c.io.writeMessage(level, msg)
}

func (c *common) verifyFinished(msg []byte, baseKey []byte) error {
	fin := parseFinished(msg)
	want := c.suite.finishedMAC(baseKey, c.transcript.h)
	if !hmac.Equal(want, fin.verifyData) {
		return alertf(AlertDecryptError, "invalid Finished verify_data")
	}
	c.transcript.write(msg)
	return nil
}

func (c *common) finished(baseKey []byte) []byte {
	m := &finishedMsg{verifyData: c.suite.finishedMAC(baseKey, c.transcript.h)}
	return m.marshal()
}

// verifyCertificateVerify checks the peer's signature over the transcript.
func (c *common) verifyCertificateVerify(msg []byte, context string, offered []SignatureScheme) error {
	cv, err := parseCertificateVerify(msg)
	if err != nil {
		return err
	}
	if !slices.Contains(offered, cv.scheme) || slices.Contains([]SignatureScheme{PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512}, cv.scheme) {
		return alertf(AlertIllegalParameter, "peer used signature scheme %v that was not offered", cv.scheme)
	}
	signed := signedMessage(context, c.transcript.sum())
	if err := verifyHandshake(c.peerCerts[0].PublicKey, cv.scheme, signed, cv.signature); err != nil {
		return alertWrap(AlertDecryptError, err)
	}
	c.peerScheme = cv.scheme
	c.transcript.write(msg)
	return nil
}

// signCertificateVerify produces our CertificateVerify message.
func (c *common) signCertificateVerify(cert *Certificate, scheme SignatureScheme, context string) ([]byte, error) {
	signed := signedMessage(context, c.transcript.sum())
	sig, err := signHandshake(c.config.rand(), cert.PrivateKey, scheme, signed)
	if err != nil {
		return nil, alertf(AlertInternalError, "signing CertificateVerify: %v", err)
	}
	m := &certificateVerifyMsg{scheme: scheme, signature: sig}
	return m.marshal(), nil
}

func unexpected(typ uint8, waiting string) error {
	return alertf(AlertUnexpectedMessage, "unexpected handshake message type %d while waiting for %s", typ, waiting)
}

// parseCertificates parses a DER chain.
func parseCertificates(chain [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, alertf(AlertBadCertificate, "parsing peer certificate: %v", err)
		}
		certs[i] = cert
	}
	return certs, nil
}

// certificateAlert maps an x509 verification error to the alert to send.
func certificateAlert(err error) Alert {
	switch e := err.(type) {
	case x509.UnknownAuthorityError:
		return AlertUnknownCA
	case x509.CertificateInvalidError:
		if e.Reason == x509.Expired {
			return AlertCertificateExpired
		}
		return AlertBadCertificate
	case x509.HostnameError:
		return AlertBadCertificate
	}
	return AlertBadCertificate
}
