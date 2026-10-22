package tls13

import (
	"crypto/rand"
	"testing"
)

// FuzzParsers feeds arbitrary bytes to every handshake message parser and
// to both state machines. Nothing may panic.
func FuzzParsers(f *testing.F) {
	ch := &clientHelloMsg{
		random:              make([]byte, 32),
		sessionID:           make([]byte, 32),
		cipherSuites:        defaultCipherSuites,
		serverName:          "example.test",
		supportedGroups:     defaultCurvePreferences,
		signatureAlgorithms: supportedSignatureAlgorithms,
		alpnProtocols:       []string{"h2", "http/1.1"},
		supportedVersions:   []uint16{versionTLS13},
		keyShares:           []keyShareEntry{{X25519, make([]byte, 32)}},
		cookie:              []byte("cookie"),
		hasQUICParams:       true,
		quicParams:          []byte{1, 2, 3},
	}
	f.Add(ch.marshal())
	sh := &serverHelloMsg{random: make([]byte, 32), cipherSuite: TLS_AES_128_GCM_SHA256, keyShare: keyShareEntry{X25519, make([]byte, 32)}}
	f.Add(sh.marshal())
	ee := &encryptedExtensionsMsg{alpnProtocol: "h3", serverNameAck: true, hasQUICParams: true, quicParams: []byte{9}}
	f.Add(ee.marshal())
	cert := &certificateMsg{certificates: [][]byte{{1, 2, 3}}}
	f.Add(cert.marshal())
	cr := &certificateRequestMsg{signatureAlgorithms: supportedSignatureAlgorithms}
	f.Add(cr.marshal())
	cv := &certificateVerifyMsg{scheme: Ed25519, signature: make([]byte, 64)}
	f.Add(cv.marshal())
	f.Add(marshalKeyUpdate(true))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		parseClientHello(data)
		parseServerHello(data)
		parseEncryptedExtensions(data)
		parseCertificateRequest(data)
		parseCertificate(data)
		parseCertificateVerify(data)
		parseNewSessionTicket(data)
		parseKeyUpdate(data)

		// Feed the message to fresh state machines as well.
		srv := QUICServer(&Config{Rand: rand.Reader}, nil)
		srv.Start()
		srv.HandleData(LevelInitial, data)

		cli := QUICClient(&Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, nil)
		if err := cli.Start(); err == nil {
			cli.HandleData(LevelInitial, data)
		}
	})
}
