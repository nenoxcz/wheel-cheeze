package tls13

import (
	"errors"
	"fmt"
)

// Alert is a TLS alert description (RFC 8446, section 6).
type Alert uint8

const (
	AlertCloseNotify                  Alert = 0
	AlertUnexpectedMessage            Alert = 10
	AlertBadRecordMAC                 Alert = 20
	AlertRecordOverflow               Alert = 22
	AlertHandshakeFailure             Alert = 40
	AlertBadCertificate               Alert = 42
	AlertUnsupportedCertificate       Alert = 43
	AlertCertificateRevoked           Alert = 44
	AlertCertificateExpired           Alert = 45
	AlertCertificateUnknown           Alert = 46
	AlertIllegalParameter             Alert = 47
	AlertUnknownCA                    Alert = 48
	AlertAccessDenied                 Alert = 49
	AlertDecodeError                  Alert = 50
	AlertDecryptError                 Alert = 51
	AlertProtocolVersion              Alert = 70
	AlertInsufficientSecurity         Alert = 71
	AlertInternalError                Alert = 80
	AlertInappropriateFallback        Alert = 86
	AlertUserCanceled                 Alert = 90
	AlertMissingExtension             Alert = 109
	AlertUnsupportedExtension         Alert = 110
	AlertUnrecognizedName             Alert = 112
	AlertBadCertificateStatusResponse Alert = 113
	AlertUnknownPSKIdentity           Alert = 115
	AlertCertificateRequired          Alert = 116
	AlertNoApplicationProtocol        Alert = 120
)

var alertNames = map[Alert]string{
	AlertCloseNotify:                  "close_notify",
	AlertUnexpectedMessage:            "unexpected_message",
	AlertBadRecordMAC:                 "bad_record_mac",
	AlertRecordOverflow:               "record_overflow",
	AlertHandshakeFailure:             "handshake_failure",
	AlertBadCertificate:               "bad_certificate",
	AlertUnsupportedCertificate:       "unsupported_certificate",
	AlertCertificateRevoked:           "certificate_revoked",
	AlertCertificateExpired:           "certificate_expired",
	AlertCertificateUnknown:           "certificate_unknown",
	AlertIllegalParameter:             "illegal_parameter",
	AlertUnknownCA:                    "unknown_ca",
	AlertAccessDenied:                 "access_denied",
	AlertDecodeError:                  "decode_error",
	AlertDecryptError:                 "decrypt_error",
	AlertProtocolVersion:              "protocol_version",
	AlertInsufficientSecurity:         "insufficient_security",
	AlertInternalError:                "internal_error",
	AlertInappropriateFallback:        "inappropriate_fallback",
	AlertUserCanceled:                 "user_canceled",
	AlertMissingExtension:             "missing_extension",
	AlertUnsupportedExtension:         "unsupported_extension",
	AlertUnrecognizedName:             "unrecognized_name",
	AlertBadCertificateStatusResponse: "bad_certificate_status_response",
	AlertUnknownPSKIdentity:           "unknown_psk_identity",
	AlertCertificateRequired:          "certificate_required",
	AlertNoApplicationProtocol:        "no_application_protocol",
}

func (a Alert) String() string {
	if s, ok := alertNames[a]; ok {
		return s
	}
	return fmt.Sprintf("alert(%d)", uint8(a))
}

// AlertError reports a fatal TLS alert.
//
// When Remote is true the peer sent the alert. Otherwise this endpoint
// detected the problem described by Err and sent (or, over QUIC, reported)
// Alert to the peer.
type AlertError struct {
	Alert  Alert
	Remote bool
	Err    error
}

func (e *AlertError) Error() string {
	if e.Remote {
		return "tls13: remote error: " + e.Alert.String()
	}
	if e.Err != nil {
		return fmt.Sprintf("tls13: %v (alert %s)", e.Err, e.Alert)
	}
	return "tls13: local error: " + e.Alert.String()
}

func (e *AlertError) Unwrap() error { return e.Err }

// alertf builds a local AlertError with a formatted cause.
func alertf(a Alert, format string, args ...any) error {
	return &AlertError{Alert: a, Err: fmt.Errorf(format, args...)}
}

// alertWrap builds a local AlertError around an existing error.
func alertWrap(a Alert, err error) error {
	return &AlertError{Alert: a, Err: err}
}

// alertFor extracts the alert that must be sent for err. Errors that are not
// AlertErrors map to internal_error.
func alertFor(err error) Alert {
	var ae *AlertError
	if errors.As(err, &ae) {
		return ae.Alert
	}
	return AlertInternalError
}
