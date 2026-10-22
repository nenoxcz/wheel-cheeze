package tls13

import "strings"

const (
	versionTLS12 uint16 = 0x0303
	versionTLS13 uint16 = 0x0304
)

// Handshake message types (RFC 8446, section 4).
const (
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeCertificateRequest  uint8 = 13
	typeCertificateVerify   uint8 = 15
	typeFinished            uint8 = 20
	typeKeyUpdate           uint8 = 24
	typeMessageHash         uint8 = 254
)

// Extension types.
const (
	extServerName              uint16 = 0
	extStatusRequest           uint16 = 5
	extSupportedGroups         uint16 = 10
	extSignatureAlgorithms     uint16 = 13
	extALPN                    uint16 = 16
	extSCT                     uint16 = 18
	extPreSharedKey            uint16 = 41
	extEarlyData               uint16 = 42
	extSupportedVersions       uint16 = 43
	extCookie                  uint16 = 44
	extPSKModes                uint16 = 45
	extCertificateAuthorities  uint16 = 47
	extSignatureAlgorithmsCert uint16 = 50
	extKeyShare                uint16 = 51
	extQUICTransportParameters uint16 = 57
)

// helloRetryRequestRandom is SHA-256("HelloRetryRequest").
var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func decodeErr(what string) error {
	return alertf(AlertDecodeError, "malformed %s", what)
}

// marshalMessage prepends the four-byte handshake header.
func marshalMessage(typ uint8, body func(*builder)) []byte {
	var b builder
	b.u8(typ)
	b.vec24(body)
	return b.buf
}

type extension struct {
	typ  uint16
	data reader
}

// parseExtensions splits an extension block, rejecting duplicates.
func parseExtensions(r reader) ([]extension, error) {
	var exts []extension
	seen := map[uint16]bool{}
	for !r.empty() {
		var e extension
		if !r.u16(&e.typ) || !r.vec16(&e.data) {
			return nil, decodeErr("extensions")
		}
		if seen[e.typ] {
			return nil, alertf(AlertIllegalParameter, "duplicate extension %d", e.typ)
		}
		seen[e.typ] = true
		exts = append(exts, e)
	}
	return exts, nil
}

func readU16List(r reader, allowEmpty bool) ([]uint16, bool) {
	if len(r)%2 != 0 || (!allowEmpty && len(r) == 0) {
		return nil, false
	}
	out := make([]uint16, 0, len(r)/2)
	for !r.empty() {
		var v uint16
		r.u16(&v)
		out = append(out, v)
	}
	return out, true
}

type keyShareEntry struct {
	group CurveID
	data  []byte
}

type clientHelloMsg struct {
	raw                []byte
	random             []byte
	sessionID          []byte
	cipherSuites       []uint16
	compressionMethods []byte

	serverName          string
	supportedGroups     []CurveID
	signatureAlgorithms []SignatureScheme
	alpnProtocols       []string
	supportedVersions   []uint16
	keyShares           []keyShareEntry
	cookie              []byte
	quicParams          []byte
	hasQUICParams       bool
	earlyData           bool
	hasPSK              bool
	extensionTypes      []uint16
}

func (m *clientHelloMsg) marshal() []byte {
	m.raw = marshalMessage(typeClientHello, func(b *builder) {
		b.u16(versionTLS12) // legacy_version
		b.raw(m.random)
		b.bytes8(m.sessionID)
		b.vec16(func(b *builder) {
			for _, s := range m.cipherSuites {
				b.u16(s)
			}
		})
		b.bytes8([]byte{0}) // legacy_compression_methods: null
		b.vec16(func(b *builder) {
			if m.serverName != "" {
				b.u16(extServerName)
				b.vec16(func(b *builder) {
					b.vec16(func(b *builder) {
						b.u8(0) // host_name
						b.bytes16([]byte(m.serverName))
					})
				})
			}
			b.u16(extSupportedGroups)
			b.vec16(func(b *builder) {
				b.vec16(func(b *builder) {
					for _, g := range m.supportedGroups {
						b.u16(uint16(g))
					}
				})
			})
			b.u16(extSignatureAlgorithms)
			b.vec16(func(b *builder) {
				b.vec16(func(b *builder) {
					for _, s := range m.signatureAlgorithms {
						b.u16(uint16(s))
					}
				})
			})
			if len(m.alpnProtocols) > 0 {
				b.u16(extALPN)
				b.vec16(func(b *builder) {
					b.vec16(func(b *builder) {
						for _, p := range m.alpnProtocols {
							b.bytes8([]byte(p))
						}
					})
				})
			}
			if len(m.cookie) > 0 {
				b.u16(extCookie)
				b.vec16(func(b *builder) { b.bytes16(m.cookie) })
			}
			b.u16(extSupportedVersions)
			b.vec16(func(b *builder) {
				b.vec8(func(b *builder) {
					for _, v := range m.supportedVersions {
						b.u16(v)
					}
				})
			})
			b.u16(extKeyShare)
			b.vec16(func(b *builder) {
				b.vec16(func(b *builder) {
					for _, ks := range m.keyShares {
						b.u16(uint16(ks.group))
						b.bytes16(ks.data)
					}
				})
			})
			if m.hasQUICParams {
				b.u16(extQUICTransportParameters)
				b.bytes16(m.quicParams)
			}
		})
	})
	return m.raw
}

func parseClientHello(raw []byte) (*clientHelloMsg, error) {
	m := &clientHelloMsg{raw: raw}
	r := reader(raw[4:])
	var legacyVersion uint16
	var suites, comp, extBlock reader
	if !r.u16(&legacyVersion) || !r.bytesN(&m.random, 32) ||
		!r.bytes8(&m.sessionID) || len(m.sessionID) > 32 ||
		!r.vec16(&suites) || !r.vec8(&comp) {
		return nil, decodeErr("ClientHello")
	}
	var ok bool
	if m.cipherSuites, ok = readU16List(suites, false); !ok {
		return nil, decodeErr("ClientHello cipher suites")
	}
	m.compressionMethods = []byte(comp)
	if r.empty() {
		// No extensions at all: a pre-TLS 1.3 client.
		return m, nil
	}
	if !r.vec16(&extBlock) || !r.empty() {
		return nil, decodeErr("ClientHello")
	}
	exts, err := parseExtensions(extBlock)
	if err != nil {
		return nil, err
	}
	for i, e := range exts {
		m.extensionTypes = append(m.extensionTypes, e.typ)
		d := e.data
		switch e.typ {
		case extServerName:
			var list reader
			if !d.vec16(&list) || !d.empty() {
				return nil, decodeErr("server_name")
			}
			for !list.empty() {
				var nameType uint8
				var name []byte
				if !list.u8(&nameType) || !list.bytes16(&name) {
					return nil, decodeErr("server_name")
				}
				if nameType != 0 {
					continue
				}
				if m.serverName != "" || len(name) == 0 {
					return nil, decodeErr("server_name")
				}
				m.serverName = strings.TrimSuffix(string(name), ".")
			}
		case extSupportedGroups:
			var list reader
			if !d.vec16(&list) || !d.empty() {
				return nil, decodeErr("supported_groups")
			}
			groups, ok := readU16List(list, false)
			if !ok {
				return nil, decodeErr("supported_groups")
			}
			for _, g := range groups {
				m.supportedGroups = append(m.supportedGroups, CurveID(g))
			}
		case extSignatureAlgorithms:
			var list reader
			if !d.vec16(&list) || !d.empty() {
				return nil, decodeErr("signature_algorithms")
			}
			algs, ok := readU16List(list, false)
			if !ok {
				return nil, decodeErr("signature_algorithms")
			}
			for _, a := range algs {
				m.signatureAlgorithms = append(m.signatureAlgorithms, SignatureScheme(a))
			}
		case extALPN:
			var list reader
			if !d.vec16(&list) || !d.empty() || list.empty() {
				return nil, decodeErr("application_layer_protocol_negotiation")
			}
			for !list.empty() {
				var p []byte
				if !list.bytes8(&p) || len(p) == 0 {
					return nil, decodeErr("application_layer_protocol_negotiation")
				}
				m.alpnProtocols = append(m.alpnProtocols, string(p))
			}
		case extSupportedVersions:
			var list reader
			if !d.vec8(&list) || !d.empty() {
				return nil, decodeErr("supported_versions")
			}
			if m.supportedVersions, ok = readU16List(list, false); !ok {
				return nil, decodeErr("supported_versions")
			}
		case extCookie:
			if !d.bytes16(&m.cookie) || !d.empty() || len(m.cookie) == 0 {
				return nil, decodeErr("cookie")
			}
		case extKeyShare:
			var list reader
			if !d.vec16(&list) || !d.empty() {
				return nil, decodeErr("key_share")
			}
			for !list.empty() {
				var g uint16
				var data []byte
				if !list.u16(&g) || !list.bytes16(&data) || len(data) == 0 {
					return nil, decodeErr("key_share")
				}
				for _, ks := range m.keyShares {
					if ks.group == CurveID(g) {
						return nil, alertf(AlertIllegalParameter, "duplicate key share for %v", CurveID(g))
					}
				}
				m.keyShares = append(m.keyShares, keyShareEntry{CurveID(g), data})
			}
		case extQUICTransportParameters:
			m.quicParams = []byte(d)
			m.hasQUICParams = true
		case extEarlyData:
			m.earlyData = true
		case extPreSharedKey:
			if i != len(exts)-1 {
				return nil, alertf(AlertIllegalParameter, "pre_shared_key is not the last extension")
			}
			m.hasPSK = true
		}
	}
	return m, nil
}

type serverHelloMsg struct {
	raw              []byte
	random           []byte
	sessionID        []byte
	cipherSuite      uint16
	compression      uint8
	supportedVersion uint16
	keyShare         keyShareEntry // ServerHello
	selectedGroup    CurveID       // HelloRetryRequest
	cookie           []byte        // HelloRetryRequest
	extensionTypes   []uint16
}

func (m *serverHelloMsg) isHRR() bool {
	return string(m.random) == string(helloRetryRequestRandom)
}

func (m *serverHelloMsg) marshal() []byte {
	m.raw = marshalMessage(typeServerHello, func(b *builder) {
		b.u16(versionTLS12)
		b.raw(m.random)
		b.bytes8(m.sessionID)
		b.u16(m.cipherSuite)
		b.u8(0)
		b.vec16(func(b *builder) {
			b.u16(extSupportedVersions)
			b.vec16(func(b *builder) { b.u16(versionTLS13) })
			b.u16(extKeyShare)
			b.vec16(func(b *builder) {
				if m.isHRR() {
					b.u16(uint16(m.selectedGroup))
				} else {
					b.u16(uint16(m.keyShare.group))
					b.bytes16(m.keyShare.data)
				}
			})
			if len(m.cookie) > 0 {
				b.u16(extCookie)
				b.vec16(func(b *builder) { b.bytes16(m.cookie) })
			}
		})
	})
	return m.raw
}

func parseServerHello(raw []byte) (*serverHelloMsg, error) {
	m := &serverHelloMsg{raw: raw}
	r := reader(raw[4:])
	var legacyVersion uint16
	var extBlock reader
	if !r.u16(&legacyVersion) || !r.bytesN(&m.random, 32) ||
		!r.bytes8(&m.sessionID) || len(m.sessionID) > 32 ||
		!r.u16(&m.cipherSuite) || !r.u8(&m.compression) {
		return nil, decodeErr("ServerHello")
	}
	if r.empty() {
		return m, nil // TLS 1.2 or older ServerHello without extensions
	}
	if !r.vec16(&extBlock) || !r.empty() {
		return nil, decodeErr("ServerHello")
	}
	exts, err := parseExtensions(extBlock)
	if err != nil {
		return nil, err
	}
	hrr := m.isHRR()
	for _, e := range exts {
		m.extensionTypes = append(m.extensionTypes, e.typ)
		d := e.data
		switch e.typ {
		case extSupportedVersions:
			if !d.u16(&m.supportedVersion) || !d.empty() {
				return nil, decodeErr("supported_versions")
			}
		case extKeyShare:
			var g uint16
			if !d.u16(&g) {
				return nil, decodeErr("key_share")
			}
			if hrr {
				m.selectedGroup = CurveID(g)
			} else {
				m.keyShare.group = CurveID(g)
				if !d.bytes16(&m.keyShare.data) || len(m.keyShare.data) == 0 {
					return nil, decodeErr("key_share")
				}
			}
			if !d.empty() {
				return nil, decodeErr("key_share")
			}
		case extCookie:
			if !d.bytes16(&m.cookie) || !d.empty() || len(m.cookie) == 0 {
				return nil, decodeErr("cookie")
			}
		}
	}
	return m, nil
}

type encryptedExtensionsMsg struct {
	raw            []byte
	alpnProtocol   string
	serverNameAck  bool
	quicParams     []byte
	hasQUICParams  bool
	earlyData      bool
	extensionTypes []uint16
}

func (m *encryptedExtensionsMsg) marshal() []byte {
	m.raw = marshalMessage(typeEncryptedExtensions, func(b *builder) {
		b.vec16(func(b *builder) {
			if m.serverNameAck {
				b.u16(extServerName)
				b.u16(0)
			}
			if m.alpnProtocol != "" {
				b.u16(extALPN)
				b.vec16(func(b *builder) {
					b.vec16(func(b *builder) { b.bytes8([]byte(m.alpnProtocol)) })
				})
			}
			if m.hasQUICParams {
				b.u16(extQUICTransportParameters)
				b.bytes16(m.quicParams)
			}
		})
	})
	return m.raw
}

func parseEncryptedExtensions(raw []byte) (*encryptedExtensionsMsg, error) {
	m := &encryptedExtensionsMsg{raw: raw}
	r := reader(raw[4:])
	var extBlock reader
	if !r.vec16(&extBlock) || !r.empty() {
		return nil, decodeErr("EncryptedExtensions")
	}
	exts, err := parseExtensions(extBlock)
	if err != nil {
		return nil, err
	}
	for _, e := range exts {
		m.extensionTypes = append(m.extensionTypes, e.typ)
		d := e.data
		switch e.typ {
		case extALPN:
			var list reader
			var proto []byte
			if !d.vec16(&list) || !d.empty() || !list.bytes8(&proto) || !list.empty() || len(proto) == 0 {
				return nil, decodeErr("application_layer_protocol_negotiation")
			}
			m.alpnProtocol = string(proto)
		case extServerName:
			if !d.empty() {
				return nil, decodeErr("server_name")
			}
			m.serverNameAck = true
		case extQUICTransportParameters:
			m.quicParams = []byte(d)
			m.hasQUICParams = true
		case extEarlyData:
			m.earlyData = true
		}
	}
	return m, nil
}

type certificateRequestMsg struct {
	raw                 []byte
	context             []byte
	signatureAlgorithms []SignatureScheme
}

func (m *certificateRequestMsg) marshal() []byte {
	m.raw = marshalMessage(typeCertificateRequest, func(b *builder) {
		b.bytes8(m.context)
		b.vec16(func(b *builder) {
			b.u16(extSignatureAlgorithms)
			b.vec16(func(b *builder) {
				b.vec16(func(b *builder) {
					for _, s := range m.signatureAlgorithms {
						b.u16(uint16(s))
					}
				})
			})
		})
	})
	return m.raw
}

func parseCertificateRequest(raw []byte) (*certificateRequestMsg, error) {
	m := &certificateRequestMsg{raw: raw}
	r := reader(raw[4:])
	var extBlock reader
	if !r.bytes8(&m.context) || !r.vec16(&extBlock) || !r.empty() {
		return nil, decodeErr("CertificateRequest")
	}
	exts, err := parseExtensions(extBlock)
	if err != nil {
		return nil, err
	}
	for _, e := range exts {
		if e.typ != extSignatureAlgorithms {
			continue
		}
		var list reader
		d := e.data
		if !d.vec16(&list) || !d.empty() {
			return nil, decodeErr("signature_algorithms")
		}
		algs, ok := readU16List(list, false)
		if !ok {
			return nil, decodeErr("signature_algorithms")
		}
		for _, a := range algs {
			m.signatureAlgorithms = append(m.signatureAlgorithms, SignatureScheme(a))
		}
	}
	if m.signatureAlgorithms == nil {
		return nil, alertf(AlertMissingExtension, "CertificateRequest without signature_algorithms")
	}
	return m, nil
}

type certificateMsg struct {
	raw          []byte
	context      []byte
	certificates [][]byte
	// hasEntryExtensions is set if any CertificateEntry carried extensions.
	hasEntryExtensions bool
}

func (m *certificateMsg) marshal() []byte {
	m.raw = marshalMessage(typeCertificate, func(b *builder) {
		b.bytes8(m.context)
		b.vec24(func(b *builder) {
			for _, c := range m.certificates {
				b.bytes24(c)
				b.u16(0) // no per-certificate extensions
			}
		})
	})
	return m.raw
}

func parseCertificate(raw []byte) (*certificateMsg, error) {
	m := &certificateMsg{raw: raw}
	r := reader(raw[4:])
	var list reader
	if !r.bytes8(&m.context) || !r.vec24(&list) || !r.empty() {
		return nil, decodeErr("Certificate")
	}
	for !list.empty() {
		var cert []byte
		var exts reader
		if !list.bytes24(&cert) || len(cert) == 0 || !list.vec16(&exts) {
			return nil, decodeErr("Certificate")
		}
		if _, err := parseExtensions(exts); err != nil {
			return nil, err
		}
		if !exts.empty() {
			m.hasEntryExtensions = true
		}
		m.certificates = append(m.certificates, cert)
	}
	return m, nil
}

type certificateVerifyMsg struct {
	raw       []byte
	scheme    SignatureScheme
	signature []byte
}

func (m *certificateVerifyMsg) marshal() []byte {
	m.raw = marshalMessage(typeCertificateVerify, func(b *builder) {
		b.u16(uint16(m.scheme))
		b.bytes16(m.signature)
	})
	return m.raw
}

func parseCertificateVerify(raw []byte) (*certificateVerifyMsg, error) {
	m := &certificateVerifyMsg{raw: raw}
	r := reader(raw[4:])
	var s uint16
	if !r.u16(&s) || !r.bytes16(&m.signature) || !r.empty() {
		return nil, decodeErr("CertificateVerify")
	}
	m.scheme = SignatureScheme(s)
	return m, nil
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) marshal() []byte {
	m.raw = marshalMessage(typeFinished, func(b *builder) { b.raw(m.verifyData) })
	return m.raw
}

func parseFinished(raw []byte) *finishedMsg {
	return &finishedMsg{raw: raw, verifyData: raw[4:]}
}

type newSessionTicketMsg struct {
	lifetime uint32
	ageAdd   uint32
	nonce    []byte
	ticket   []byte
}

func parseNewSessionTicket(raw []byte) (*newSessionTicketMsg, error) {
	m := &newSessionTicketMsg{}
	r := reader(raw[4:])
	var exts reader
	if !r.u32(&m.lifetime) || !r.u32(&m.ageAdd) || !r.bytes8(&m.nonce) ||
		!r.bytes16(&m.ticket) || len(m.ticket) == 0 || !r.vec16(&exts) || !r.empty() {
		return nil, decodeErr("NewSessionTicket")
	}
	if _, err := parseExtensions(exts); err != nil {
		return nil, err
	}
	return m, nil
}

func marshalKeyUpdate(requestUpdate bool) []byte {
	return marshalMessage(typeKeyUpdate, func(b *builder) {
		if requestUpdate {
			b.u8(1)
		} else {
			b.u8(0)
		}
	})
}

func parseKeyUpdate(raw []byte) (requestUpdate bool, err error) {
	r := reader(raw[4:])
	var v uint8
	if !r.u8(&v) || !r.empty() {
		return false, decodeErr("KeyUpdate")
	}
	switch v {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, alertf(AlertIllegalParameter, "invalid KeyUpdate request_update value %d", v)
}
