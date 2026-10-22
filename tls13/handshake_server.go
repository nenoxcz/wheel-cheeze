package tls13

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
)

type serverState int

const (
	serverWaitClientHello serverState = iota
	serverWaitClientHello2
	serverWaitClientCertificate
	serverWaitClientCertificateVerify
	serverWaitFinished
	serverConnected
)

type serverHandshake struct {
	common
	st serverState

	hello         *clientHelloMsg
	cert          *Certificate
	certRequested bool
	// Selected before a HelloRetryRequest and fixed for ClientHello2.
	hrrSuite *CipherSuite
	hrrGroup CurveID
}

func newServerHandshake(config *Config, io handshakeIO, isQUIC bool, quicParams []byte) *serverHandshake {
	return &serverHandshake{common: common{
		config:          config,
		io:              io,
		isQUIC:          isQUIC,
		localQUICParams: quicParams,
	}}
}

func (hs *serverHandshake) start() error { return nil }

func (hs *serverHandshake) handleMessage(level Level, msg []byte) error {
	typ := msg[0]
	switch hs.st {
	case serverWaitClientHello, serverWaitClientHello2:
		if typ != typeClientHello || level != LevelInitial {
			return unexpected(typ, "ClientHello")
		}
		return hs.handleClientHello(msg)
	case serverWaitClientCertificate:
		if typ != typeCertificate || level != LevelHandshake {
			return unexpected(typ, "client Certificate")
		}
		return hs.handleClientCertificate(msg)
	case serverWaitClientCertificateVerify:
		if typ != typeCertificateVerify || level != LevelHandshake {
			return unexpected(typ, "client CertificateVerify")
		}
		if err := hs.verifyCertificateVerify(msg, clientSignatureContext, supportedSignatureAlgorithms); err != nil {
			return err
		}
		hs.st = serverWaitFinished
		return nil
	case serverWaitFinished:
		if typ != typeFinished || level != LevelHandshake {
			return unexpected(typ, "client Finished")
		}
		if err := hs.verifyFinished(msg, hs.ks.clientHandshakeSecret); err != nil {
			return err
		}
		hs.io.setReadSecret(LevelApplication, hs.suite, hs.ks.clientAppSecret)
		hs.done = true
		hs.st = serverConnected
		return nil
	}
	return unexpected(typ, "nothing")
}

// negotiate picks the cipher suite, group, certificate and ALPN protocol for
// a ClientHello.
func (hs *serverHandshake) negotiate(ch *clientHelloMsg) (needHRR bool, err error) {
	cfg := hs.config
	if !slices.Contains(ch.supportedVersions, versionTLS13) {
		return false, alertf(AlertProtocolVersion, "client does not support TLS 1.3")
	}
	if len(ch.compressionMethods) != 1 || ch.compressionMethods[0] != 0 {
		return false, alertf(AlertIllegalParameter, "client offered compression")
	}
	if hs.isQUIC {
		if len(ch.sessionID) != 0 {
			return false, alertf(AlertIllegalParameter, "non-empty legacy_session_id over QUIC")
		}
		if !ch.hasQUICParams {
			return false, alertf(AlertMissingExtension, "client did not send quic_transport_parameters")
		}
	}
	if ch.signatureAlgorithms == nil {
		return false, alertf(AlertMissingExtension, "client did not send signature_algorithms")
	}
	if ch.supportedGroups == nil || !slices.Contains(ch.extensionTypes, extKeyShare) {
		return false, alertf(AlertMissingExtension, "client did not send supported_groups and key_share")
	}

	// Cipher suite: server preference.
	hs.suite = nil
	for _, id := range cfg.cipherSuites() {
		if slices.Contains(ch.cipherSuites, id) {
			hs.suite = CipherSuiteByID(id)
			break
		}
	}
	if hs.suite == nil {
		return false, alertf(AlertHandshakeFailure, "no cipher suite in common with the client")
	}

	// Group: prefer one the client already sent a share for, to avoid a
	// HelloRetryRequest round trip.
	prefs := cfg.curvePreferences()
	hs.group = 0
	for _, g := range prefs {
		if !slices.Contains(ch.supportedGroups, g) {
			continue
		}
		for _, ks := range ch.keyShares {
			if ks.group == g {
				hs.group = g
				break
			}
		}
		if hs.group != 0 {
			break
		}
	}
	if hs.group == 0 {
		for _, g := range prefs {
			if slices.Contains(ch.supportedGroups, g) {
				hs.group = g
				needHRR = true
				break
			}
		}
	}
	if hs.group == 0 {
		return false, alertf(AlertHandshakeFailure, "no key exchange group in common with the client")
	}

	// Certificate and signature scheme.
	hs.serverName = ch.serverName
	hs.cert = nil
	if cfg.GetCertificate != nil {
		cert, err := cfg.GetCertificate(ch.serverName)
		if err != nil {
			return false, alertWrap(AlertUnrecognizedName, err)
		}
		hs.cert = cert
	} else {
		for i := range cfg.Certificates {
			c := &cfg.Certificates[i]
			if c.PrivateKey == nil {
				continue
			}
			if _, err := selectSignatureScheme(c.PrivateKey.Public(), ch.signatureAlgorithms); err == nil {
				hs.cert = c
				break
			}
		}
	}
	if hs.cert == nil || len(hs.cert.Certificate) == 0 || hs.cert.PrivateKey == nil {
		return false, alertf(AlertHandshakeFailure, "no usable server certificate for the client's signature algorithms")
	}

	// ALPN: server preference.
	hs.alpn = ""
	if len(ch.alpnProtocols) > 0 && len(cfg.NextProtos) > 0 {
		for _, p := range cfg.NextProtos {
			if slices.Contains(ch.alpnProtocols, p) {
				hs.alpn = p
				break
			}
		}
		if hs.alpn == "" {
			return false, alertf(AlertNoApplicationProtocol, "client offered ALPN %q, none of which is supported", ch.alpnProtocols)
		}
	}
	if hs.isQUIC && hs.alpn == "" {
		return false, alertf(AlertNoApplicationProtocol, "QUIC requires an application protocol")
	}
	return needHRR, nil
}

func (hs *serverHandshake) handleClientHello(msg []byte) error {
	ch, err := parseClientHello(msg)
	if err != nil {
		return err
	}
	if hs.st == serverWaitClientHello2 {
		if len(ch.keyShares) != 1 || ch.keyShares[0].group != hs.hrrGroup {
			return alertf(AlertIllegalParameter, "second ClientHello does not contain exactly the requested %v key share", hs.hrrGroup)
		}
		if string(ch.sessionID) != string(hs.hello.sessionID) {
			return alertf(AlertIllegalParameter, "second ClientHello changed legacy_session_id")
		}
	}
	hs.hello = ch
	if hs.clientRandom == nil {
		hs.clientRandom = ch.random
	}

	needHRR, err := hs.negotiate(ch)
	if err != nil {
		return err
	}
	if hs.isQUIC {
		hs.peerParams = ch.quicParams
	}
	if hs.st == serverWaitClientHello2 {
		if needHRR || hs.suite != hs.hrrSuite || hs.group != hs.hrrGroup {
			return alertf(AlertIllegalParameter, "second ClientHello is inconsistent with the HelloRetryRequest")
		}
	} else if needHRR {
		return hs.sendHelloRetryRequest(msg)
	}

	var clientShare []byte
	for _, ks := range ch.keyShares {
		if ks.group == hs.group {
			clientShare = ks.data
		}
	}
	serverShare, secret, err := serverKeyExchange(hs.config.rand(), hs.group, clientShare)
	if err != nil {
		return alertWrap(AlertIllegalParameter, err)
	}

	if hs.transcript.h == nil {
		hs.transcript.setHash(hs.suite.newHash())
	}
	hs.transcript.write(msg)

	sh := &serverHelloMsg{
		random:      make([]byte, 32),
		sessionID:   ch.sessionID,
		cipherSuite: hs.suite.ID,
		keyShare:    keyShareEntry{hs.group, serverShare},
	}
	if _, err := io.ReadFull(hs.config.rand(), sh.random); err != nil {
		return fmt.Errorf("tls13: reading random: %w", err)
	}
	hs.send(LevelInitial, sh.marshal())
	if !hs.isQUIC && !hs.didHRR && len(ch.sessionID) > 0 {
		hs.io.sendChangeCipherSpec()
	}

	hs.ks.suite = hs.suite
	hs.ks.deriveHandshake(secret, hs.transcript.h)
	cfg := hs.config
	cfg.writeKeyLog(keyLogClientHandshake, hs.clientRandom, hs.ks.clientHandshakeSecret)
	cfg.writeKeyLog(keyLogServerHandshake, hs.clientRandom, hs.ks.serverHandshakeSecret)
	hs.io.setWriteSecret(LevelHandshake, hs.suite, hs.ks.serverHandshakeSecret)
	hs.io.setReadSecret(LevelHandshake, hs.suite, hs.ks.clientHandshakeSecret)

	ee := &encryptedExtensionsMsg{
		alpnProtocol:  hs.alpn,
		serverNameAck: ch.serverName != "",
		quicParams:    hs.localQUICParams,
		hasQUICParams: hs.isQUIC,
	}
	hs.send(LevelHandshake, ee.marshal())

	if cfg.ClientAuth != NoClientCert {
		cr := &certificateRequestMsg{signatureAlgorithms: supportedSignatureAlgorithms}
		hs.send(LevelHandshake, cr.marshal())
		hs.certRequested = true
	}

	cm := &certificateMsg{certificates: hs.cert.Certificate}
	hs.send(LevelHandshake, cm.marshal())

	scheme, err := selectSignatureScheme(hs.cert.PrivateKey.Public(), ch.signatureAlgorithms)
	if err != nil {
		return alertWrap(AlertHandshakeFailure, err)
	}
	cv, err := hs.signCertificateVerify(hs.cert, scheme, serverSignatureContext)
	if err != nil {
		return err
	}
	hs.send(LevelHandshake, cv)
	hs.send(LevelHandshake, hs.finished(hs.ks.serverHandshakeSecret))

	hs.ks.deriveApplication(hs.transcript.h)
	cfg.writeKeyLog(keyLogClientTraffic, hs.clientRandom, hs.ks.clientAppSecret)
	cfg.writeKeyLog(keyLogServerTraffic, hs.clientRandom, hs.ks.serverAppSecret)
	cfg.writeKeyLog(keyLogExporter, hs.clientRandom, hs.ks.exporterSecret)
	hs.io.setWriteSecret(LevelApplication, hs.suite, hs.ks.serverAppSecret)

	if hs.certRequested {
		hs.st = serverWaitClientCertificate
	} else {
		hs.st = serverWaitFinished
	}
	return nil
}

func (hs *serverHandshake) sendHelloRetryRequest(ch1 []byte) error {
	hs.hrrSuite = hs.suite
	hs.hrrGroup = hs.group
	hs.didHRR = true
	hs.transcript.setHash(hs.suite.newHash())
	hs.transcript.write(ch1)
	hs.transcript.restartForHRR(hs.suite.newHash)

	hrr := &serverHelloMsg{
		random:        helloRetryRequestRandom,
		sessionID:     hs.hello.sessionID,
		cipherSuite:   hs.suite.ID,
		selectedGroup: hs.group,
	}
	hs.send(LevelInitial, hrr.marshal())
	if !hs.isQUIC && len(hs.hello.sessionID) > 0 {
		hs.io.sendChangeCipherSpec()
	}
	hs.st = serverWaitClientHello2
	return nil
}

func (hs *serverHandshake) handleClientCertificate(msg []byte) error {
	cm, err := parseCertificate(msg)
	if err != nil {
		return err
	}
	if len(cm.context) != 0 {
		return alertf(AlertIllegalParameter, "unexpected certificate_request_context in client Certificate")
	}
	hs.transcript.write(msg)
	cfg := hs.config
	if len(cm.certificates) == 0 {
		if cfg.ClientAuth == RequireAnyClientCert || cfg.ClientAuth == RequireAndVerifyClientCert {
			return alertf(AlertCertificateRequired, "client did not provide a certificate")
		}
		hs.st = serverWaitFinished
		return nil
	}
	certs, err := parseCertificates(cm.certificates)
	if err != nil {
		return err
	}
	hs.peerCerts = certs
	if cfg.ClientAuth == VerifyClientCertIfGiven || cfg.ClientAuth == RequireAndVerifyClientCert {
		if cfg.ClientCAs == nil {
			return alertWrap(AlertInternalError, errors.New("client certificate verification requires ClientCAs"))
		}
		opts := x509.VerifyOptions{
			Roots:         cfg.ClientCAs,
			CurrentTime:   cfg.now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
	hs.st = serverWaitClientCertificateVerify
	return nil
}
