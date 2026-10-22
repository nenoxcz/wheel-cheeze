package quic

import "time"

// Config configures QUIC connections. The zero value is usable.
type Config struct {
	// HandshakeTimeout bounds connection establishment. Default 10s.
	HandshakeTimeout time.Duration
	// MaxIdleTimeout closes the connection after this long without
	// network activity. The effective value is the minimum of both peers'.
	// Default 30s.
	MaxIdleTimeout time.Duration
	// KeepAlivePeriod, if set, sends a PING after this much idle time so
	// the connection (and NAT bindings) stay alive.
	KeepAlivePeriod time.Duration

	// InitialStreamReceiveWindow is the per-stream flow control window.
	// Default 1 MiB.
	InitialStreamReceiveWindow uint64
	// InitialConnectionReceiveWindow is the connection flow control
	// window. Default 4 MiB.
	InitialConnectionReceiveWindow uint64
	// MaxIncomingStreams and MaxIncomingUniStreams limit concurrent
	// streams opened by the peer. Default 100 each; negative means none.
	MaxIncomingStreams    int64
	MaxIncomingUniStreams int64

	// RequireAddressValidation makes a server answer every new client
	// with a Retry packet first (RFC 9000, section 8.1.2).
	RequireAddressValidation bool

	// Logf, if set, receives a trace of connection events.
	Logf func(format string, args ...any)
}

func (c *Config) withDefaults() *Config {
	out := Config{}
	if c != nil {
		out = *c
	}
	if out.HandshakeTimeout <= 0 {
		out.HandshakeTimeout = 10 * time.Second
	}
	if out.MaxIdleTimeout <= 0 {
		out.MaxIdleTimeout = 30 * time.Second
	}
	if out.InitialStreamReceiveWindow == 0 {
		out.InitialStreamReceiveWindow = 1 << 20
	}
	if out.InitialConnectionReceiveWindow == 0 {
		out.InitialConnectionReceiveWindow = 4 << 20
	}
	if out.MaxIncomingStreams == 0 {
		out.MaxIncomingStreams = 100
	} else if out.MaxIncomingStreams < 0 {
		out.MaxIncomingStreams = 0
	}
	if out.MaxIncomingUniStreams == 0 {
		out.MaxIncomingUniStreams = 100
	} else if out.MaxIncomingUniStreams < 0 {
		out.MaxIncomingUniStreams = 0
	}
	return &out
}
