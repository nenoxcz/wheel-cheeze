package tls13

// A minimal length-prefixed encoder/decoder for TLS presentation-language
// structures (RFC 8446, section 3).

type builder struct {
	buf []byte
}

func (b *builder) u8(v uint8)   { b.buf = append(b.buf, v) }
func (b *builder) u16(v uint16) { b.buf = append(b.buf, byte(v>>8), byte(v)) }
func (b *builder) u24(v int)    { b.buf = append(b.buf, byte(v>>16), byte(v>>8), byte(v)) }
func (b *builder) u32(v uint32) {
	b.buf = append(b.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func (b *builder) raw(p []byte) { b.buf = append(b.buf, p...) }

// vec writes a length-prefixed block whose contents are produced by f. The
// length prefix is lenSize bytes wide.
func (b *builder) vec(lenSize int, f func(*builder)) {
	start := len(b.buf)
	for i := 0; i < lenSize; i++ {
		b.buf = append(b.buf, 0)
	}
	f(b)
	n := len(b.buf) - start - lenSize
	if n >= 1<<(8*lenSize) {
		panic("tls13: length-prefixed vector too long")
	}
	for i := 0; i < lenSize; i++ {
		b.buf[start+lenSize-1-i] = byte(n >> (8 * i))
	}
}

func (b *builder) vec8(f func(*builder))  { b.vec(1, f) }
func (b *builder) vec16(f func(*builder)) { b.vec(2, f) }
func (b *builder) vec24(f func(*builder)) { b.vec(3, f) }

func (b *builder) bytes8(p []byte)  { b.vec8(func(b *builder) { b.raw(p) }) }
func (b *builder) bytes16(p []byte) { b.vec16(func(b *builder) { b.raw(p) }) }
func (b *builder) bytes24(p []byte) { b.vec24(func(b *builder) { b.raw(p) }) }

// reader consumes a byte string. Every method returns false, without
// consuming anything, if not enough input is left.
type reader []byte

func (r *reader) empty() bool { return len(*r) == 0 }

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) u8(out *uint8) bool {
	v, ok := r.take(1)
	if !ok {
		return false
	}
	*out = v[0]
	return true
}

func (r *reader) u16(out *uint16) bool {
	v, ok := r.take(2)
	if !ok {
		return false
	}
	*out = uint16(v[0])<<8 | uint16(v[1])
	return true
}

func (r *reader) u24(out *int) bool {
	v, ok := r.take(3)
	if !ok {
		return false
	}
	*out = int(v[0])<<16 | int(v[1])<<8 | int(v[2])
	return true
}

func (r *reader) u32(out *uint32) bool {
	v, ok := r.take(4)
	if !ok {
		return false
	}
	*out = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	return true
}

func (r *reader) bytesN(out *[]byte, n int) bool {
	v, ok := r.take(n)
	if !ok {
		return false
	}
	*out = v
	return true
}

func (r *reader) vec(lenSize int, out *reader) bool {
	orig := *r
	lb, ok := r.take(lenSize)
	if !ok {
		return false
	}
	n := 0
	for _, c := range lb {
		n = n<<8 | int(c)
	}
	v, ok := r.take(n)
	if !ok {
		*r = orig
		return false
	}
	*out = reader(v)
	return true
}

func (r *reader) vec8(out *reader) bool  { return r.vec(1, out) }
func (r *reader) vec16(out *reader) bool { return r.vec(2, out) }
func (r *reader) vec24(out *reader) bool { return r.vec(3, out) }

func (r *reader) bytes8(out *[]byte) bool {
	var v reader
	if !r.vec8(&v) {
		return false
	}
	*out = []byte(v)
	return true
}

func (r *reader) bytes16(out *[]byte) bool {
	var v reader
	if !r.vec16(&v) {
		return false
	}
	*out = []byte(v)
	return true
}

func (r *reader) bytes24(out *[]byte) bool {
	var v reader
	if !r.vec24(&v) {
		return false
	}
	*out = []byte(v)
	return true
}
