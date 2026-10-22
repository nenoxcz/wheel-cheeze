package quic

import "time"

// Loss detection and congestion control (RFC 9002).

const (
	packetThreshold = 3
	granularity     = time.Millisecond
	initialRTT      = 333 * time.Millisecond

	// maxDatagramSize is the UDP payload size used for sending. 1200 bytes
	// is the minimum every QUIC path must support, so no path MTU
	// discovery is needed.
	maxDatagramSize = 1200
	initialWindow   = 10 * maxDatagramSize
	minimumWindow   = 2 * maxDatagramSize
)

type frameKind uint8

const (
	fkCrypto frameKind = iota
	fkStream
	fkAck
	fkMaxData
	fkMaxStreamData
	fkMaxStreamsBidi
	fkMaxStreamsUni
	fkHandshakeDone
	fkResetStream
	fkStopSending
	fkRetireCID
	fkPing
)

// sentFrame records what a packet carried so it can be retransmitted if
// the packet is lost.
type sentFrame struct {
	kind   frameKind
	id     uint64 // stream ID, sequence number, or largest acked for fkAck
	offset uint64
	length uint64
	fin    bool
}

type sentPacket struct {
	pn           uint64
	sentTime     time.Time
	size         int
	ackEliciting bool
	inFlight     bool
	frames       []sentFrame
}

type rttStats struct {
	latest    time.Duration
	smoothed  time.Duration
	rttvar    time.Duration
	min       time.Duration
	hasSample bool
}

func newRTTStats() rttStats {
	return rttStats{smoothed: initialRTT, rttvar: initialRTT / 2}
}

// update applies an RTT sample (RFC 9002, section 5.3).
func (r *rttStats) update(latest, ackDelay time.Duration) {
	r.latest = latest
	if !r.hasSample {
		r.hasSample = true
		r.min = latest
		r.smoothed = latest
		r.rttvar = latest / 2
		return
	}
	r.min = min(r.min, latest)
	adjusted := latest
	if latest >= r.min+ackDelay {
		adjusted = latest - ackDelay
	}
	diff := r.smoothed - adjusted
	if diff < 0 {
		diff = -diff
	}
	r.rttvar = (3*r.rttvar + diff) / 4
	r.smoothed = (7*r.smoothed + adjusted) / 8
}

// pto returns the base probe timeout without max_ack_delay or backoff.
func (r *rttStats) pto() time.Duration {
	return r.smoothed + max(4*r.rttvar, granularity)
}

// lossDelay is the time threshold for declaring a packet lost.
func (r *rttStats) lossDelay() time.Duration {
	d := max(r.latest, r.smoothed) * 9 / 8
	return max(d, granularity)
}

// congestionController implements NewReno (RFC 9002, section 7).
type congestionController struct {
	window        int
	bytesInFlight int
	ssthresh      int
	recoveryStart time.Time
}

func newCongestionController() congestionController {
	return congestionController{window: initialWindow, ssthresh: 1 << 62}
}

func (cc *congestionController) canSend(n int) bool {
	return cc.bytesInFlight+n <= cc.window
}

func (cc *congestionController) onSent(p *sentPacket) {
	if p.inFlight {
		cc.bytesInFlight += p.size
	}
}

func (cc *congestionController) onAcked(p *sentPacket) {
	if !p.inFlight {
		return
	}
	cc.bytesInFlight -= p.size
	if !p.sentTime.After(cc.recoveryStart) {
		return // sent before the current recovery period
	}
	if cc.window < cc.ssthresh {
		cc.window += p.size
	} else {
		cc.window += maxDatagramSize * p.size / cc.window
	}
}

func (cc *congestionController) onLost(p *sentPacket) {
	if p.inFlight {
		cc.bytesInFlight -= p.size
	}
}

// onCongestionEvent reacts to loss of a packet sent at sentTime.
func (cc *congestionController) onCongestionEvent(sentTime, now time.Time) {
	if !sentTime.After(cc.recoveryStart) {
		return
	}
	cc.recoveryStart = now
	cc.ssthresh = max(cc.window/2, minimumWindow)
	cc.window = cc.ssthresh
}

// discard forgets packets of a space whose keys were dropped.
func (cc *congestionController) discard(p *sentPacket) {
	if p.inFlight {
		cc.bytesInFlight -= p.size
	}
}
