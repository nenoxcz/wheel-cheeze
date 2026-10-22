package quic

import (
	"errors"
	"fmt"

	"github.com/nenoxcz/wheel-cheeze/tls13"
)

// TransportErrorCode is a QUIC transport error code (RFC 9000, 20.1).
type TransportErrorCode uint64

const (
	NoError                 TransportErrorCode = 0x0
	InternalError           TransportErrorCode = 0x1
	ConnectionRefused       TransportErrorCode = 0x2
	FlowControlError        TransportErrorCode = 0x3
	StreamLimitError        TransportErrorCode = 0x4
	StreamStateError        TransportErrorCode = 0x5
	FinalSizeError          TransportErrorCode = 0x6
	FrameEncodingError      TransportErrorCode = 0x7
	TransportParameterError TransportErrorCode = 0x8
	ConnectionIDLimitError  TransportErrorCode = 0x9
	ProtocolViolation       TransportErrorCode = 0xa
	InvalidToken            TransportErrorCode = 0xb
	ApplicationErrorCode    TransportErrorCode = 0xc
	CryptoBufferExceeded    TransportErrorCode = 0xd
	KeyUpdateError          TransportErrorCode = 0xe
	AEADLimitReached        TransportErrorCode = 0xf
	NoViablePath            TransportErrorCode = 0x10
	cryptoErrorBase         TransportErrorCode = 0x100
)

var transportErrorNames = map[TransportErrorCode]string{
	NoError:                 "NO_ERROR",
	InternalError:           "INTERNAL_ERROR",
	ConnectionRefused:       "CONNECTION_REFUSED",
	FlowControlError:        "FLOW_CONTROL_ERROR",
	StreamLimitError:        "STREAM_LIMIT_ERROR",
	StreamStateError:        "STREAM_STATE_ERROR",
	FinalSizeError:          "FINAL_SIZE_ERROR",
	FrameEncodingError:      "FRAME_ENCODING_ERROR",
	TransportParameterError: "TRANSPORT_PARAMETER_ERROR",
	ConnectionIDLimitError:  "CONNECTION_ID_LIMIT_ERROR",
	ProtocolViolation:       "PROTOCOL_VIOLATION",
	InvalidToken:            "INVALID_TOKEN",
	ApplicationErrorCode:    "APPLICATION_ERROR",
	CryptoBufferExceeded:    "CRYPTO_BUFFER_EXCEEDED",
	KeyUpdateError:          "KEY_UPDATE_ERROR",
	AEADLimitReached:        "AEAD_LIMIT_REACHED",
	NoViablePath:            "NO_VIABLE_PATH",
}

func (c TransportErrorCode) String() string {
	if c.IsCryptoError() {
		return fmt.Sprintf("CRYPTO_ERROR(%s)", tls13.Alert(c-cryptoErrorBase))
	}
	if s, ok := transportErrorNames[c]; ok {
		return s
	}
	return fmt.Sprintf("transport error %#x", uint64(c))
}

// IsCryptoError reports whether the code carries a TLS alert.
func (c TransportErrorCode) IsCryptoError() bool {
	return c >= cryptoErrorBase && c < cryptoErrorBase+0x100
}

// TransportError is a connection error signalled with a transport
// CONNECTION_CLOSE frame (type 0x1c).
type TransportError struct {
	Code      TransportErrorCode
	FrameType uint64
	Reason    string
	// Remote is set when the peer closed the connection.
	Remote bool
	// TLSError holds the TLS failure behind a local CRYPTO_ERROR.
	TLSError error
}

func (e *TransportError) Error() string {
	who := "local"
	if e.Remote {
		who = "peer"
	}
	msg := fmt.Sprintf("quic: %s closed the connection: %v", who, e.Code)
	if e.TLSError != nil {
		return msg + ": " + e.TLSError.Error()
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

func (e *TransportError) Unwrap() error { return e.TLSError }

// ApplicationError is a connection closed by an application (type 0x1d).
type ApplicationError struct {
	Code   uint64
	Reason string
	Remote bool
}

func (e *ApplicationError) Error() string {
	who := "local"
	if e.Remote {
		who = "peer"
	}
	if e.Reason != "" {
		return fmt.Sprintf("quic: %s application closed the connection with code %#x: %s", who, e.Code, e.Reason)
	}
	return fmt.Sprintf("quic: %s application closed the connection with code %#x", who, e.Code)
}

// StreamError reports a stream reset by RESET_STREAM or STOP_SENDING.
type StreamError struct {
	StreamID uint64
	Code     uint64
	Remote   bool
}

func (e *StreamError) Error() string {
	who := "locally"
	if e.Remote {
		who = "by peer"
	}
	return fmt.Sprintf("quic: stream %d reset %s with code %#x", e.StreamID, who, e.Code)
}

// VersionNegotiationError is returned when the server does not support
// QUIC version 1.
type VersionNegotiationError struct {
	Offered []uint32
}

func (e *VersionNegotiationError) Error() string {
	return fmt.Sprintf("quic: server does not support QUIC v1 (it offered %#x)", e.Offered)
}

var (
	// ErrIdleTimeout is returned when the connection was idle too long.
	ErrIdleTimeout = errors.New("quic: connection idle timeout")
	// ErrHandshakeTimeout is returned when the handshake does not complete
	// within Config.HandshakeTimeout. Typically the server is unreachable
	// or UDP is blocked.
	ErrHandshakeTimeout = errors.New("quic: handshake timeout (no response from server; UDP may be blocked)")
	// ErrStatelessReset is returned when the peer sent a stateless reset.
	ErrStatelessReset = errors.New("quic: received a stateless reset")
	// ErrClosed is returned for operations on a closed connection.
	ErrClosed = errors.New("quic: connection closed")
)

func transportErr(code TransportErrorCode, format string, args ...any) *TransportError {
	return &TransportError{Code: code, Reason: fmt.Sprintf(format, args...)}
}
