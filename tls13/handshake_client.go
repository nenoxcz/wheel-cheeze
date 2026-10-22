package tls13

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
)

type clientState int

const (
	clientStart clientState = iota
	clientWaitServerHello
	clientWaitEncryptedExtensions
	clientWaitCertificateOrRequest
	clientWaitCertificate
	clientWaitCertificateVerify
	clientWaitFinished
	clientConnected
)

type clientHandshake struct {
	common
	st clientState

	hello     *clientHelloMsg
	keyShares []*clientKeyShare
	offered   map[uint16]bool // extension types sent in ClientHello
	hrrSuite  *CipherSuite
	sentCCS   bool
	certReq   *certificateRequestMsg
}

func newClientHandshake(config *Config, io handshakeIO, isQUIC bool, quicParams []byte) *clientHandshake {
	return &clientHandshake{common: common{
		config:          config,
		io:              io,
		isQUIC:          isQUIC,
		localQUICParams: quicParams,
	}}
}

// hostnameInSNI returns the value to send in server_name: IP literals are
// not allowed there (RFC 6066, section 3).
func hostnameInSNI(name string) string {
	host := strings.TrimSuffix(name, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func (hs *clientHandshake) start() error {
	cfg := hs.config
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		return errors.New("tls13: either ServerName or InsecureSkipVerify must be set")
	}
	hs.serverName = cfg.ServerName

	m := &clientHelloMsg{
		random:              make([]byte, 32),
		cipherSuites:        cfg.cipherSuites(),
		serverName:          hostnameInSNI(cfg.ServerName),
		supportedGroups:     cfg.curvePreferences(),
		signatureAlgorithms: supportedSignatureAlgorithms,
		alpnProtocols:       cfg.NextProtos,
		supportedVersions:   []uint16{versionTLS13},
	}
	if len(m.cipherSuites) == 0 || len(m.supportedGroups) == 0 {
		return errors.New("tls13: no supported cipher suites or groups configured")
	}
	if _, err := io.ReadFull(cfg.rand(), m.random); err != nil {
		return fmt.Errorf("tls13: reading random: %w", err)
	}
	if !hs.isQUIC {
		// Middlebox compatibility mode (RFC 8446, appendix D.4). QUIC
		// forbids it (RFC 9001, section 8.4).
		m.sessionID = make([]byte, 32)
		if _, err := io.ReadFull(cfg.rand(), m.sessionID); err != nil {
			return fmt.Errorf("tls13: reading random: %w", err)
		}
	} else {
		m.hasQUICParams = true
		m.quicParams = hs.localQUICParams
	}

	shareGroups := m.supportedGroups[:1]
	if m.supportedGroups[0] == X25519MLKEM768 && len(m.supportedGroups) > 1 {
		// Also offer a classical share so servers without ML-KEM support
		// avoid a HelloRetryRequest round trip.
		shareGroups = m.supportedGroups[:2]
	}
	for _, g := range shareGroups {
		ks, err := generateKeyShare(cfg.rand(), g)
		if err != nil {
			return err
		}
		hs.keyShares = append(hs.keyShares, ks)
		m.keyShares = append(m.keyShares, keyShareEntry{g, ks.public})
	}

	hs.hello = m
	hs.clientRandom = m.random
	hs.offered = map[uint16]bool{
		extSupportedGroups:     true,
		extSignatureAlgorithms: true,
		extSupportedVersions:   true,
		extKeyShare:            true,
	}
	if m.serverName != "" {
		hs.offered[extServerName] = true
	}
	if len(m.alpnProtocols) > 0 {
		hs.offered[extALPN] = true
	}
	if m.hasQUICParams {
		hs.offered[extQUICTransportParameters] = true
	}
	hs.send(LevelInitial, m.marshal())
	hs.st = clientWaitServerHello
	return nil
}

func (hs *clientHandshake) handleMessage(level Level, msg []byte) error {
	typ := msg[0]
	switch hs.st {
	case clientWaitServerHello:
		if typ != typeServerHello || level != LevelInitial {
			return unexpected(typ, "ServerHello")
		}
		return hs.handleServerHello(msg)
	case clientWaitEncryptedExtensions:
		if typ != typeEncryptedExtensions || level != LevelHandshake {
			return unexpected(typ, "EncryptedExtensions")
		}
		return hs.handleEncryptedExtensions(msg)
	case clientWaitCertificateOrRequest:
		if level != LevelHandshake {
			return unexpected(typ, "Certificate")
		}
		if typ == typeCertificateRequest {
			return hs.handleCertificateRequest(msg)
		}
		if typ != typeCertificate {
			return unexpected(typ, "Certificate")
		}
		return hs.handleCertificate(msg)
	case clientWaitCertificate:
		if typ != typeCertificate || level != LevelHandshake {
			return unexpected(typ, "Certificate")
		}
		return hs.handleCertificate(msg)
	case clientWaitCertificateVerify:
		if typ != typeCertificateVerify || level != LevelHandshake {
			return unexpected(typ, "CertificateVerify")
		}
		if err := hs.verifyCertificateVerify(msg, serverSignatureContext, supportedSignatureAlgorithms); err != nil {
			return err
		}
		hs.st = clientWaitFinished
		return nil
	case clientWaitFinished:
		if typ != typeFinished || level != LevelHandshake {
			return unexpected(typ, "Finished")
		}
		return hs.handleFinished(msg)
	}
	return unexpected(typ, "nothing")
}

// checkResponseExtensions enforces RFC 8446, section 4.2: responses may only
// carry extensions the client offered, and only in the right message.
func (hs *clientHandshake) checkResponseExtensions(types []uint16, allowed []uint16, where string) error {
	for _, t := range types {
		if t == extCookie && where == "HelloRetryRequest" {
			continue // the one extension a server may send unsolicited
		}
		if !hs.offered[t] {
			return alertf(AlertUnsupportedExtension, "%s contains unsolicited extension %d", where, t)
		}
		if !slices.Contains(allowed, t) {
			return alertf(AlertIllegalParameter, "extension %d is not allowed in %s", t, where)
		}
	}
	return nil
}

func (hs *clientHandshake) handleServerHello(msg []byte) error {
	sh, err := parseServerHello(msg)
	if err != nil {
		return err
	}
	if sh.supportedVersion != versionTLS13 {
		if sh.supportedVersion == 0 {
			return alertf(AlertProtocolVersion, "server does not support TLS 1.3 (it selected legacy version %#04x)", parseLegacyVersion(msg))
		}
		return alertf(AlertIllegalParameter, "server selected unsupported version %#04x", sh.supportedVersion)
	}
	if string(sh.sessionID) != string(hs.hello.sessionID) {
		return alertf(AlertIllegalParameter, "server echoed a different legacy_session_id")
	}
	if sh.compression != 0 {
		return alertf(AlertIllegalParameter, "server selected a compression method")
	}
	if !slices.Contains(hs.hello.cipherSuites, sh.cipherSuite) {
		return alertf(AlertIllegalParameter, "server selected cipher suite %#04x that was not offered", sh.cipherSuite)
	}
	suite := CipherSuiteByID(sh.cipherSuite)

	if sh.isHRR() {
		if err := hs.checkResponseExtensions(sh.extensionTypes, []uint16{extKeyShare, extSupportedVersions, extCookie}, "HelloRetryRequest"); err != nil {
			return err
		}
		return hs.handleHelloRetryRequest(sh, suite)
	}
	if err := hs.checkResponseExtensions(sh.extensionTypes, []uint16{extKeyShare, extSupportedVersions}, "ServerHello"); err != nil {
		return err
	}
	if hs.hrrSuite != nil && hs.hrrSuite != suite {
		return alertf(AlertIllegalParameter, "server changed cipher suite after HelloRetryRequest")
	}

	var share *clientKeyShare
	for _, ks := range hs.keyShares {
		if ks.group == sh.keyShare.group {
			share = ks
		}
	}
	if share == nil {
		return alertf(AlertIllegalParameter, "server selected group %v without a matching key share", sh.keyShare.group)
	}
	secret, err := share.sharedSecret(sh.keyShare.data)
	if err != nil {
		return alertWrap(AlertIllegalParameter, err)
	}

	hs.suite = suite
	hs.group = share.group
	hs.ks.suite = suite
	if hs.transcript.h == nil {
		hs.transcript.setHash(suite.newHash())
	}
	hs.transcript.write(msg)
	hs.ks.deriveHandshake(secret, hs.transcript.h)
	hs.keyShares = nil

	hs.config.writeKeyLog(keyLogClientHandshake, hs.clientRandom, hs.ks.clientHandshakeSecret)
	hs.config.writeKeyLog(keyLogServerHandshake, hs.clientRandom, hs.ks.serverHandshakeSecret)
	hs.io.setReadSecret(LevelHandshake, suite, hs.ks.serverHandshakeSecret)
	hs.io.setWriteSecret(LevelHandshake, suite, hs.ks.clientHandshakeSecret)
	hs.st = clientWaitEncryptedExtensions
	return nil
}

func parseLegacyVersion(msg []byte) uint16 {
	if len(msg) < 6 {
		return 0
	}
	return uint16(msg[4])<<8 | uint16(msg[5])
}

func (hs *clientHandshake) handleHelloRetryRequest(hrr *serverHelloMsg, suite *CipherSuite) error {
	if hs.hrrSuite != nil {
		return alertf(AlertUnexpectedMessage, "received a second HelloRetryRequest")
	}
	m := hs.hello
	if hrr.selectedGroup != 0 {
		if !slices.Contains(m.supportedGroups, hrr.selectedGroup) {
			return alertf(AlertIllegalParameter, "HelloRetryRequest selected group %v that was not offered", hrr.selectedGroup)
		}
		for _, ks := range hs.keyShares {
			if ks.group == hrr.selectedGroup {
				return alertf(AlertIllegalParameter, "HelloRetryRequest selected group %v that already had a key share", hrr.selectedGroup)
			}
		}
	} else if len(hrr.cookie) == 0 {
		return alertf(AlertIllegalParameter, "HelloRetryRequest would not change the ClientHello")
	}

	hs.hrrSuite = suite
	hs.didHRR = true
	hs.transcript.setHash(suite.newHash())
	hs.transcript.restartForHRR(suite.newHash)
	hs.transcript.write(hrr.raw)

	if hrr.selectedGroup != 0 {
		ks, err := generateKeyShare(hs.config.rand(), hrr.selectedGroup)
		if err != nil {
			return err
		}
		hs.keyShares = []*clientKeyShare{ks}
		m.keyShares = []keyShareEntry{{ks.group, ks.public}}
	}
	m.cookie = hrr.cookie
	if !hs.isQUIC {
		hs.io.sendChangeCipherSpec()
		hs.sentCCS = true
	}
	hs.send(LevelInitial, m.marshal())
	return nil
}

func (hs *clientHandshake) handleEncryptedExtensions(msg []byte) error {
	ee, err := parseEncryptedExtensions(msg)
	if err != nil {
		return err
	}
	allowed := []uint16{extServerName, extSupportedGroups, extALPN, extQUICTransportParameters, extEarlyData}
	if err := hs.checkResponseExtensions(ee.extensionTypes, allowed, "EncryptedExtensions"); err != nil {
		return err
	}
	if ee.alpnProtocol != "" && !slices.Contains(hs.hello.alpnProtocols, ee.alpnProtocol) {
		return alertf(AlertIllegalParameter, "server selected ALPN protocol %q that was not offered", ee.alpnProtocol)
	}
	if hs.isQUIC {
		if ee.alpnProtocol == "" {
			return alertf(AlertNoApplicationProtocol, "server did not negotiate an application protocol")
		}
		if !ee.hasQUICParams {
			return alertf(AlertMissingExtension, "server did not send quic_transport_parameters")
		}
		hs.peerParams = ee.quicParams
	}
	hs.alpn = ee.alpnProtocol
	hs.transcript.write(msg)
	hs.st = clientWaitCertificateOrRequest
	return nil
}

func (hs *clientHandshake) handleCertificateRequest(msg []byte) error {
	cr, err := parseCertificateRequest(msg)
	if err != nil {
		return err
	}
	if len(cr.context) != 0 {
		return alertf(AlertIllegalParameter, "non-empty certificate_request_context during the handshake")
	}
	hs.certReq = cr
	hs.transcript.write(msg)
	hs.st = clientWaitCertificate
	return nil
}

func (hs *clientHandshake) handleCertificate(msg []byte) error {
	cm, err := parseCertificate(msg)
	if err != nil {
		return err
	}
	if len(cm.context) != 0 {
		return alertf(AlertIllegalParameter, "non-empty certificate_request_context in server Certificate")
	}
	if len(cm.certificates) == 0 {
		return alertf(AlertDecodeError, "server sent an empty certificate chain")
	}
	if cm.hasEntryExtensions {
		return alertf(AlertUnsupportedExtension, "server sent unsolicited certificate extensions")
	}
	certs, err := parseCertificates(cm.certificates)
	if err != nil {
		return err
	}
	hs.peerCerts = certs

	cfg := hs.config
	if !cfg.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         cfg.RootCAs,
			CurrentTime:   cfg.now(),
			DNSName:       strings.TrimSuffix(cfg.ServerName, "."),
			Intermediates: x509.NewCertPool(),
		}
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
		chains, err := certs[0].Verify(opts)
		if err != nil {
			return &AlertError{Alert: certificateAlert(err), Err: err}
		}
		hs.verifiedChains = chains
	}
	if cfg.VerifyPeerCertificate != nil {
		if err := cfg.VerifyPeerCertificate(cm.certificates, hs.verifiedChains); err != nil {
			return alertWrap(AlertBadCertificate, err)
		}
	}
	hs.transcript.write(msg)
	hs.st = clientWaitCertificateVerify
	return nil
}

func (hs *clientHandshake) handleFinished(msg []byte) error {
	if err := hs.verifyFinished(msg, hs.ks.serverHandshakeSecret); err != nil {
		return err
	}
	hs.ks.deriveApplication(hs.transcript.h)
	cfg := hs.config
	cfg.writeKeyLog(keyLogClientTraffic, hs.clientRandom, hs.ks.clientAppSecret)
	cfg.writeKeyLog(keyLogServerTraffic, hs.clientRandom, hs.ks.serverAppSecret)
	cfg.writeKeyLog(keyLogExporter, hs.clientRandom, hs.ks.exporterSecret)
	hs.io.setReadSecret(LevelApplication, hs.suite, hs.ks.serverAppSecret)

	if !hs.isQUIC && !hs.sentCCS {
		hs.io.sendChangeCipherSpec()
		hs.sentCCS = true
	}
	if hs.certReq != nil {
		if err := hs.sendClientCertificate(); err != nil {
			return err
		}
	}
	hs.send(LevelHandshake, hs.finished(hs.ks.clientHandshakeSecret))
	hs.io.setWriteSecret(LevelApplication, hs.suite, hs.ks.clientAppSecret)
	hs.done = true
	hs.st = clientConnected
	return nil
}

func (hs *clientHandshake) sendClientCertificate() error {
	var cert *Certificate
	var scheme SignatureScheme
	for i := range hs.config.Certificates {
		c := &hs.config.Certificates[i]
		if c.PrivateKey == nil {
			continue
		}
		if s, err := selectSignatureScheme(c.PrivateKey.Public(), hs.certReq.signatureAlgorithms); err == nil {
			cert, scheme = c, s
			break
		}
	}
	cm := &certificateMsg{context: hs.certReq.context}
	if cert != nil {
		cm.certificates = cert.Certificate
	}
	hs.send(LevelHandshake, cm.marshal())
	if cert == nil {
		return nil
	}
	cv, err := hs.signCertificateVerify(cert, scheme, clientSignatureContext)
	if err != nil {
		return err
	}
	hs.send(LevelHandshake, cv)
	return nil
}
