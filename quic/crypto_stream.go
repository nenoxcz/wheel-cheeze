package quic

// maxCryptoBuffer bounds out-of-order CRYPTO data held per level.
const maxCryptoBuffer = 64 << 10

// cryptoStream carries TLS handshake bytes for one packet number space.
type cryptoStream struct {
	// Sending. Handshake flights are small, so everything written is kept
	// until the space is discarded.
	sendBuf []byte
	pending rangeSet
	acked   rangeSet

	// Receiving.
	recvOffset uint64
	segments   map[uint64][]byte
}

func (s *cryptoStream) write(data []byte) {
	start := uint64(len(s.sendBuf))
	s.sendBuf = append(s.sendBuf, data...)
	s.pending.add(start, uint64(len(s.sendBuf)))
}

func (s *cryptoStream) hasPending() bool { return !s.pending.empty() }

// next pops up to limit bytes of pending data.
func (s *cryptoStream) next(limit int) (offset uint64, data []byte) {
	if s.pending.empty() || limit <= 0 {
		return 0, nil
	}
	r := s.pending[0]
	end := min(r.end, r.start+uint64(limit))
	s.pending.remove(r.start, end)
	return r.start, s.sendBuf[r.start:end]
}

func (s *cryptoStream) requeue(offset, n uint64) {
	for _, r := range missing(s.acked, offset, offset+n) {
		s.pending.add(r.start, r.end)
	}
}

func (s *cryptoStream) ack(offset, n uint64) {
	s.acked.add(offset, offset+n)
	s.pending.remove(offset, offset+n)
}

// resendAll queues every byte again, after a Retry.
func (s *cryptoStream) resendAll() {
	s.acked = nil
	s.pending = nil
	s.pending.add(0, uint64(len(s.sendBuf)))
}

// recv stores a CRYPTO frame and returns any newly contiguous data.
func (s *cryptoStream) recv(offset uint64, data []byte) ([]byte, *TransportError) {
	end := offset + uint64(len(data))
	if end <= s.recvOffset {
		return nil, nil // duplicate
	}
	if end-s.recvOffset > maxCryptoBuffer {
		return nil, transportErr(CryptoBufferExceeded, "CRYPTO data too far ahead")
	}
	if offset > s.recvOffset {
		if s.segments == nil {
			s.segments = map[uint64][]byte{}
		}
		if old, ok := s.segments[offset]; !ok || len(old) < len(data) {
			s.segments[offset] = append([]byte(nil), data...)
		}
		return nil, nil
	}
	out := append([]byte(nil), data[s.recvOffset-offset:]...)
	s.recvOffset = end
	// Pull in buffered segments that are now contiguous.
	for progress := true; progress; {
		progress = false
		for off, seg := range s.segments {
			segEnd := off + uint64(len(seg))
			if off > s.recvOffset {
				continue
			}
			delete(s.segments, off)
			if segEnd > s.recvOffset {
				out = append(out, seg[s.recvOffset-off:]...)
				s.recvOffset = segEnd
			}
			progress = true
		}
	}
	return out, nil
}

// missing returns the parts of [start, end) not covered by set.
func missing(set rangeSet, start, end uint64) []span {
	var out []span
	cur := start
	for _, r := range set {
		if r.end <= cur {
			continue
		}
		if r.start >= end {
			break
		}
		if r.start > cur {
			out = append(out, span{cur, r.start})
		}
		cur = max(cur, r.end)
		if cur >= end {
			break
		}
	}
	if cur < end {
		out = append(out, span{cur, end})
	}
	return out
}
