package quic

// Variable-length integer encoding (RFC 9000, section 16).

const maxVarint = 1<<62 - 1

func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	case v <= maxVarint:
		return 8
	}
	panic("quic: varint out of range")
}

func appendVarint(b []byte, v uint64) []byte {
	switch varintLen(v) {
	case 1:
		return append(b, byte(v))
	case 2:
		return append(b, 0x40|byte(v>>8), byte(v))
	case 4:
		return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, 0xc0|byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// appendVarint2 always uses the two-byte encoding; used for length fields
// that are patched after the payload size is known.
func appendVarint2(b []byte, v uint64) []byte {
	if v >= 1<<14 {
		panic("quic: value does not fit a two-byte varint")
	}
	return append(b, 0x40|byte(v>>8), byte(v))
}

// readVarint decodes a varint, returning the value and the number of bytes
// consumed, or n == 0 if b is too short.
func readVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}
