package quic

import (
	"fmt"
	"time"
)

// Transport parameter IDs (RFC 9000, section 18.2).
const (
	tpOriginalDestinationConnectionID = 0x00
	tpMaxIdleTimeout                  = 0x01
	tpStatelessResetToken             = 0x02
	tpMaxUDPPayloadSize               = 0x03
	tpInitialMaxData                  = 0x04
	tpInitialMaxStreamDataBidiLocal   = 0x05
	tpInitialMaxStreamDataBidiRemote  = 0x06
	tpInitialMaxStreamDataUni         = 0x07
	tpInitialMaxStreamsBidi           = 0x08
	tpInitialMaxStreamsUni            = 0x09
	tpAckDelayExponent                = 0x0a
	tpMaxAckDelay                     = 0x0b
	tpDisableActiveMigration          = 0x0c
	tpPreferredAddress                = 0x0d
	tpActiveConnectionIDLimit         = 0x0e
	tpInitialSourceConnectionID       = 0x0f
	tpRetrySourceConnectionID         = 0x10
)

type transportParameters struct {
	originalDestinationCID []byte
	hasOriginalDCID        bool
	maxIdleTimeout         time.Duration
	statelessResetToken    []byte
	maxUDPPayloadSize      uint64
	initialMaxData         uint64
	maxStreamDataBidiLocal uint64
	maxStreamDataBidiRem   uint64
	maxStreamDataUni       uint64
	maxStreamsBidi         uint64
	maxStreamsUni          uint64
	ackDelayExponent       uint64
	maxAckDelay            time.Duration
	disableActiveMigration bool
	activeConnIDLimit      uint64
	initialSourceCID       []byte
	hasInitialSourceCID    bool
	retrySourceCID         []byte
	hasRetrySourceCID      bool
}

func defaultTransportParameters() transportParameters {
	return transportParameters{
		maxUDPPayloadSize: 65527,
		ackDelayExponent:  3,
		maxAckDelay:       25 * time.Millisecond,
		activeConnIDLimit: 2,
	}
}

func (p *transportParameters) marshal(isServer bool) []byte {
	var b []byte
	putInt := func(id, v uint64) {
		b = appendVarint(b, id)
		b = appendVarint(b, uint64(varintLen(v)))
		b = appendVarint(b, v)
	}
	putBytes := func(id uint64, v []byte) {
		b = appendVarint(b, id)
		b = appendVarint(b, uint64(len(v)))
		b = append(b, v...)
	}
	if isServer {
		putBytes(tpOriginalDestinationConnectionID, p.originalDestinationCID)
		if p.hasRetrySourceCID {
			putBytes(tpRetrySourceConnectionID, p.retrySourceCID)
		}
		if len(p.statelessResetToken) == 16 {
			putBytes(tpStatelessResetToken, p.statelessResetToken)
		}
	}
	putInt(tpMaxIdleTimeout, uint64(p.maxIdleTimeout/time.Millisecond))
	putInt(tpMaxUDPPayloadSize, p.maxUDPPayloadSize)
	putInt(tpInitialMaxData, p.initialMaxData)
	putInt(tpInitialMaxStreamDataBidiLocal, p.maxStreamDataBidiLocal)
	putInt(tpInitialMaxStreamDataBidiRemote, p.maxStreamDataBidiRem)
	putInt(tpInitialMaxStreamDataUni, p.maxStreamDataUni)
	putInt(tpInitialMaxStreamsBidi, p.maxStreamsBidi)
	putInt(tpInitialMaxStreamsUni, p.maxStreamsUni)
	putInt(tpAckDelayExponent, p.ackDelayExponent)
	putInt(tpMaxAckDelay, uint64(p.maxAckDelay/time.Millisecond))
	if p.disableActiveMigration {
		putBytes(tpDisableActiveMigration, nil)
	}
	putInt(tpActiveConnectionIDLimit, p.activeConnIDLimit)
	putBytes(tpInitialSourceConnectionID, p.initialSourceCID)
	return b
}

// parseTransportParameters decodes and validates the peer's parameters.
// fromServer selects the server-only checks.
func parseTransportParameters(b []byte, fromServer bool) (*transportParameters, error) {
	p := defaultTransportParameters()
	seen := map[uint64]bool{}
	bad := func(format string, args ...any) error {
		return transportErr(TransportParameterError, format, args...)
	}
	for len(b) > 0 {
		id, n := readVarint(b)
		if n == 0 {
			return nil, bad("truncated transport parameter")
		}
		b = b[n:]
		l, n := readVarint(b)
		if n == 0 || uint64(len(b)-n) < l {
			return nil, bad("truncated transport parameter %#x", id)
		}
		val := b[n : n+int(l)]
		b = b[n+int(l):]
		if seen[id] {
			return nil, bad("duplicate transport parameter %#x", id)
		}
		seen[id] = true

		intVal := func() (uint64, error) {
			v, n := readVarint(val)
			if n == 0 || n != len(val) {
				return 0, bad("malformed integer transport parameter %#x", id)
			}
			return v, nil
		}
		var err error
		var v uint64
		switch id {
		case tpOriginalDestinationConnectionID, tpStatelessResetToken, tpPreferredAddress, tpRetrySourceConnectionID:
			if !fromServer {
				return nil, bad("client sent server-only transport parameter %#x", id)
			}
		}
		switch id {
		case tpOriginalDestinationConnectionID:
			p.originalDestinationCID, p.hasOriginalDCID = append([]byte{}, val...), true
		case tpMaxIdleTimeout:
			v, err = intVal()
			p.maxIdleTimeout = time.Duration(v) * time.Millisecond
		case tpStatelessResetToken:
			if len(val) != 16 {
				return nil, bad("stateless_reset_token must be 16 bytes")
			}
			p.statelessResetToken = append([]byte{}, val...)
		case tpMaxUDPPayloadSize:
			v, err = intVal()
			if err == nil && v < 1200 {
				return nil, bad("max_udp_payload_size %d below 1200", v)
			}
			p.maxUDPPayloadSize = v
		case tpInitialMaxData:
			p.initialMaxData, err = intVal()
		case tpInitialMaxStreamDataBidiLocal:
			p.maxStreamDataBidiLocal, err = intVal()
		case tpInitialMaxStreamDataBidiRemote:
			p.maxStreamDataBidiRem, err = intVal()
		case tpInitialMaxStreamDataUni:
			p.maxStreamDataUni, err = intVal()
		case tpInitialMaxStreamsBidi:
			p.maxStreamsBidi, err = intVal()
			if err == nil && p.maxStreamsBidi > 1<<60 {
				return nil, bad("initial_max_streams_bidi too large")
			}
		case tpInitialMaxStreamsUni:
			p.maxStreamsUni, err = intVal()
			if err == nil && p.maxStreamsUni > 1<<60 {
				return nil, bad("initial_max_streams_uni too large")
			}
		case tpAckDelayExponent:
			p.ackDelayExponent, err = intVal()
			if err == nil && p.ackDelayExponent > 20 {
				return nil, bad("ack_delay_exponent above 20")
			}
		case tpMaxAckDelay:
			v, err = intVal()
			if err == nil && v >= 1<<14 {
				return nil, bad("max_ack_delay too large")
			}
			p.maxAckDelay = time.Duration(v) * time.Millisecond
		case tpDisableActiveMigration:
			if len(val) != 0 {
				return nil, bad("disable_active_migration must be empty")
			}
			p.disableActiveMigration = true
		case tpPreferredAddress:
			// Accepted but unused: this implementation does not migrate.
		case tpActiveConnectionIDLimit:
			p.activeConnIDLimit, err = intVal()
			if err == nil && p.activeConnIDLimit < 2 {
				return nil, bad("active_connection_id_limit below 2")
			}
		case tpInitialSourceConnectionID:
			p.initialSourceCID, p.hasInitialSourceCID = append([]byte{}, val...), true
		case tpRetrySourceConnectionID:
			p.retrySourceCID, p.hasRetrySourceCID = append([]byte{}, val...), true
		}
		if err != nil {
			return nil, err
		}
	}
	if !p.hasInitialSourceCID {
		return nil, bad("missing initial_source_connection_id")
	}
	if fromServer && !p.hasOriginalDCID {
		return nil, bad("missing original_destination_connection_id")
	}
	return &p, nil
}

func (p *transportParameters) String() string {
	return fmt.Sprintf("idle=%v max_data=%d bidi=%d/%d/%d streams=%d/%d ack_delay=%v",
		p.maxIdleTimeout, p.initialMaxData, p.maxStreamDataBidiLocal, p.maxStreamDataBidiRem,
		p.maxStreamDataUni, p.maxStreamsBidi, p.maxStreamsUni, p.maxAckDelay)
}
