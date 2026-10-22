package quic

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewConnectionIDRotation(t *testing.T) {
	c := newConn(true, nil, nil, nil)
	c.dcid = []byte{0, 0, 0, 0}
	ncid := func(seq, retire uint64, b byte) newConnectionIDFrame {
		return newConnectionIDFrame{seq: seq, retirePriorTo: retire, cid: bytes.Repeat([]byte{b}, 8)}
	}

	if err := c.onNewConnectionID(ncid(1, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.dcid, []byte{0, 0, 0, 0}) {
		t.Fatalf("switched connection ID without being asked to")
	}
	// Retransmission of the same frame is fine; reusing a sequence number
	// for a different ID is not.
	if err := c.onNewConnectionID(ncid(1, 0, 1)); err != nil {
		t.Fatal(err)
	}
	var te *TransportError
	if err := c.onNewConnectionID(ncid(1, 0, 9)); !errors.As(err, &te) || te.Code != ProtocolViolation {
		t.Fatalf("got %v", err)
	}

	// retire_prior_to=2 retires seq 0 (in use) and 1: switch to seq 2.
	if err := c.onNewConnectionID(ncid(2, 2, 2)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.dcid, bytes.Repeat([]byte{2}, 8)) || c.activePeerSeq != 2 {
		t.Fatalf("dcid %x seq %d", c.dcid, c.activePeerSeq)
	}
	if len(c.pendingRetire) != 2 || c.pendingRetire[0] != 0 || c.pendingRetire[1] != 1 {
		t.Fatalf("pending RETIRE_CONNECTION_ID %v", c.pendingRetire)
	}

	// An ID that is already below retire_prior_to is retired at once.
	if err := c.onNewConnectionID(ncid(1, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if len(c.pendingRetire) != 3 {
		t.Fatalf("pending RETIRE_CONNECTION_ID %v", c.pendingRetire)
	}

	// Exceeding active_connection_id_limit is an error.
	for seq := uint64(3); seq < 3+activeConnIDLimit; seq++ {
		err := c.onNewConnectionID(ncid(seq, 2, byte(seq)))
		if seq < 2+activeConnIDLimit && err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if seq == 2+activeConnIDLimit {
			if !errors.As(err, &te) || te.Code != ConnectionIDLimitError {
				t.Fatalf("seq %d: got %v", seq, err)
			}
		}
	}
}
