package quic

import (
	"errors"
	"io"
	"os"
	"time"
)

// maxStreamSendBuffer bounds unacknowledged data buffered per stream;
// Write blocks while it is full.
const maxStreamSendBuffer = 1 << 20

// Stream ID helpers (RFC 9000, section 2.1).
func streamIsUni(id uint64) bool    { return id&0x2 != 0 }
func streamIsServer(id uint64) bool { return id&0x1 != 0 }
func streamIndex(id uint64) uint64  { return id >> 2 }
func streamID(index uint64, server, uni bool) uint64 {
	id := index << 2
	if server {
		id |= 1
	}
	if uni {
		id |= 2
	}
	return id
}

// Stream is a QUIC stream. Bidirectional streams support both Read and
// Write; unidirectional streams only one of them. Methods may be called
// concurrently with each other, except that Read (and Write) must not be
// called concurrently with itself.
type Stream struct {
	c  *Conn
	id uint64

	// Send side.
	hasSend      bool
	sendBuf      []byte // unacknowledged data starting at sendBase
	sendBase     uint64
	writeOffset  uint64 // total bytes written by the application
	pending      rangeSet
	acked        rangeSet
	maxSent      uint64 // highest offset sent so far
	peerMaxData  uint64 // MAX_STREAM_DATA from the peer
	finWritten   bool
	finPending   bool
	finAcked     bool
	sendErr      *StreamError
	resetPending bool
	resetAcked   bool

	// Receive side.
	hasRecv              bool
	recvBuf              []byte // contiguous data not yet read
	readOffset           uint64
	recvOffset           uint64 // readOffset + len(recvBuf)
	segments             map[uint64][]byte
	highestRecv          uint64
	finalSize            uint64
	finalKnown           bool
	recvErr              *StreamError
	recvMaxData          uint64
	maxStreamDataPending bool
	readCanceled         bool
	stopPending          bool
	stopCode             uint64

	readDeadline  time.Time
	writeDeadline time.Time
	notify        chan struct{}
	queued        bool // in c.sendQueue
	released      bool
}

func newStream(c *Conn, id uint64, hasSend, hasRecv bool, sendLimit, recvWindow uint64) *Stream {
	return &Stream{
		c:           c,
		id:          id,
		hasSend:     hasSend,
		hasRecv:     hasRecv,
		peerMaxData: sendLimit,
		recvMaxData: recvWindow,
		notify:      make(chan struct{}),
	}
}

// StreamID returns the stream's QUIC stream ID.
func (s *Stream) StreamID() uint64 { return s.id }

// signal wakes goroutines blocked on this stream. The caller holds c.mu.
func (s *Stream) signal() {
	close(s.notify)
	s.notify = make(chan struct{})
}

// wait blocks until the stream is signalled, the deadline passes or the
// connection terminates. It is called with c.mu held and returns with it
// held.
func (s *Stream) wait(deadline time.Time) error {
	ch := s.notify
	c := s.c
	c.mu.Unlock()
	defer c.mu.Lock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case <-ch:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	case <-c.done:
		return nil
	}
}

// Write writes data to the stream, blocking while the send buffer is full.
func (s *Stream) Write(p []byte) (int, error) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if !s.hasSend {
		return 0, errors.New("quic: write on a receive-only stream")
	}
	n := 0
	for len(p) > 0 {
		if s.sendErr != nil {
			return n, s.sendErr
		}
		if s.finWritten {
			return n, errors.New("quic: write on closed stream")
		}
		if c.closeErr != nil {
			return n, c.closeErr
		}
		if room := maxStreamSendBuffer - len(s.sendBuf); room > 0 {
			k := min(room, len(p))
			s.sendBuf = append(s.sendBuf, p[:k]...)
			s.pending.add(s.writeOffset, s.writeOffset+uint64(k))
			s.writeOffset += uint64(k)
			p = p[k:]
			n += k
			c.queueStream(s)
			c.wake()
			continue
		}
		if err := s.wait(s.writeDeadline); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Close ends the send side of the stream (sends FIN). Use CancelRead to
// stop receiving.
func (s *Stream) Close() error {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if !s.hasSend {
		return errors.New("quic: close of a receive-only stream")
	}
	if s.finWritten || s.sendErr != nil {
		return nil
	}
	s.finWritten = true
	s.finPending = true
	c.queueStream(s)
	c.wake()
	return nil
}

// CancelWrite abandons the send side with RESET_STREAM.
func (s *Stream) CancelWrite(code uint64) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	s.resetSendLocked(code, false)
}

func (s *Stream) resetSendLocked(code uint64, remote bool) {
	if !s.hasSend || s.sendErr != nil || s.finAcked {
		return
	}
	s.sendErr = &StreamError{StreamID: s.id, Code: code, Remote: remote}
	s.pending = nil
	s.finPending = false
	s.resetPending = true
	s.c.queueStream(s)
	s.c.wake()
	s.signal()
}

// CancelRead asks the peer to stop sending with STOP_SENDING and discards
// buffered data.
func (s *Stream) CancelRead(code uint64) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if !s.hasRecv || s.readCanceled || s.recvErr != nil || (s.finalKnown && s.recvOffset == s.finalSize) {
		return
	}
	s.readCanceled = true
	s.stopCode = code
	s.stopPending = true
	// Everything received so far counts as consumed for connection-level
	// flow control.
	c.consumed(s, s.highestRecv-s.readOffset)
	s.readOffset = s.highestRecv
	s.recvBuf = nil
	s.segments = nil
	c.queueStream(s)
	c.wake()
	s.signal()
}

// Read reads data from the stream. It returns io.EOF after the peer's FIN.
func (s *Stream) Read(p []byte) (int, error) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if !s.hasRecv {
		return 0, errors.New("quic: read on a send-only stream")
	}
	for {
		if len(s.recvBuf) > 0 {
			n := copy(p, s.recvBuf)
			s.recvBuf = s.recvBuf[n:]
			if len(s.recvBuf) == 0 {
				s.recvBuf = nil
			}
			s.readOffset += uint64(n)
			c.consumed(s, uint64(n))
			return n, nil
		}
		if s.recvErr != nil {
			return 0, s.recvErr
		}
		if s.readCanceled {
			return 0, errors.New("quic: read on a stream after CancelRead")
		}
		if s.finalKnown && s.readOffset == s.finalSize {
			c.maybeRelease(s)
			return 0, io.EOF
		}
		if c.closeErr != nil {
			return 0, c.closeErr
		}
		if err := s.wait(s.readDeadline); err != nil {
			return 0, err
		}
	}
}

// SetReadDeadline sets the deadline for future and pending Read calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.readDeadline = t
	s.signal()
	return nil
}

// SetWriteDeadline sets the deadline for future and pending Write calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.writeDeadline = t
	s.signal()
	return nil
}

// SetDeadline sets both deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

// Methods below are called by the connection with c.mu held.

func (s *Stream) hasWork() bool {
	return s.resetPending || s.stopPending || s.maxStreamDataPending ||
		(s.sendErr == nil && (!s.pending.empty() || s.finPending))
}

// sendable reports whether the stream has something it can send now, given
// connCredit bytes of connection-level credit.
func (s *Stream) sendable(connCredit uint64) bool {
	if s.resetPending || s.stopPending || s.maxStreamDataPending {
		return true
	}
	if s.sendErr != nil {
		return false
	}
	if !s.pending.empty() {
		start := s.pending[0].start
		return start < s.peerMaxData && (start < s.maxSent || connCredit > 0)
	}
	return s.finPending && s.maxSent == s.writeOffset
}

// nextFrame pops the next STREAM frame that fits in limit bytes, given
// connCredit bytes of connection-level flow control credit for new data.
// ok is false if nothing can be sent.
func (s *Stream) nextFrame(limit int, connCredit uint64) (off uint64, data []byte, fin bool, newBytes uint64, ok bool) {
	if s.sendErr != nil {
		return 0, nil, false, 0, false
	}
	if s.pending.empty() {
		if s.finPending && s.maxSent == s.writeOffset && streamFrameOverhead(s.id, s.writeOffset, 0) <= limit {
			s.finPending = false
			return s.writeOffset, nil, true, 0, true
		}
		return 0, nil, false, 0, false
	}
	r := s.pending[0]
	start := r.start
	end := min(r.end, s.peerMaxData)
	if start < s.maxSent {
		end = min(end, s.maxSent+connCredit)
	} else {
		end = min(end, start+connCredit)
	}
	if end <= start {
		return 0, nil, false, 0, false // flow control blocked
	}
	overhead := streamFrameOverhead(s.id, start, int(end-start))
	if overhead >= limit {
		return 0, nil, false, 0, false
	}
	if uint64(limit-overhead) < end-start {
		end = start + uint64(limit-overhead)
	}
	s.pending.remove(start, end)
	if end > s.maxSent {
		newBytes = end - max(start, s.maxSent)
		s.maxSent = end
	}
	fin = s.finPending && end == s.writeOffset
	if fin {
		s.finPending = false
	}
	return start, s.sendBuf[start-s.sendBase : end-s.sendBase], fin, newBytes, true
}

func (s *Stream) onLost(off, n uint64, fin bool) {
	if s.sendErr != nil {
		return
	}
	// Bytes below sendBase were acknowledged and dropped from the buffer.
	end := off + n
	off = max(off, s.sendBase)
	for _, r := range missing(s.acked, off, max(end, off)) {
		s.pending.add(r.start, r.end)
	}
	if fin && !s.finAcked {
		s.finPending = true
	}
}

func (s *Stream) onAcked(off, n uint64, fin bool) {
	s.acked.add(off, off+n)
	s.pending.remove(off, off+n) // may have been queued again by a probe
	if fin {
		s.finAcked = true
	}
	// Drop acknowledged data from the front of the buffer.
	if len(s.acked) > 0 && s.acked[0].start <= s.sendBase && s.acked[0].end > s.sendBase {
		drop := s.acked[0].end - s.sendBase
		s.sendBuf = s.sendBuf[drop:]
		s.sendBase += drop
		s.acked.trimBelow(s.sendBase)
		s.signal()
	}
}

func (s *Stream) sendDone() bool {
	return !s.hasSend || (s.finAcked && s.sendBase == s.writeOffset) || s.resetAcked
}

func (s *Stream) recvDone() bool {
	return !s.hasRecv || s.recvErr != nil || (s.finalKnown && s.readOffset == s.finalSize)
}

// insert stores received STREAM data and wakes readers if any of it became
// readable.
func (s *Stream) insert(off uint64, data []byte) {
	end := off + uint64(len(data))
	if end <= s.recvOffset {
		return
	}
	if off > s.recvOffset {
		if s.segments == nil {
			s.segments = map[uint64][]byte{}
		}
		if old, ok := s.segments[off]; !ok || len(old) < len(data) {
			s.segments[off] = append([]byte(nil), data...)
		}
		return
	}
	s.recvBuf = append(s.recvBuf, data[s.recvOffset-off:]...)
	s.recvOffset = end
	for progress := len(s.segments) > 0; progress; {
		progress = false
		for o, seg := range s.segments {
			if o > s.recvOffset {
				continue
			}
			delete(s.segments, o)
			if segEnd := o + uint64(len(seg)); segEnd > s.recvOffset {
				s.recvBuf = append(s.recvBuf, seg[s.recvOffset-o:]...)
				s.recvOffset = segEnd
			}
			progress = true
		}
	}
	s.signal()
}
