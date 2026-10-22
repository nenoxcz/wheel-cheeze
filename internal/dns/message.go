// Package dns is a small stub resolver that speaks the DNS wire protocol
// (RFC 1035) directly over UDP and TCP. Unlike the system resolver it
// reports exactly what each server answered (NXDOMAIN, SERVFAIL, REFUSED,
// an empty answer, or nothing at all), which is what a network diagnosis
// needs.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Type is a resource record type.
type Type uint16

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypeAAAA  Type = 28
	TypeOPT   Type = 41
)

func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// RCode is a response code.
type RCode uint8

const (
	RCodeSuccess  RCode = 0
	RCodeFormErr  RCode = 1
	RCodeServFail RCode = 2
	RCodeNXDomain RCode = 3
	RCodeNotImp   RCode = 4
	RCodeRefused  RCode = 5
)

func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "NOERROR"
	case RCodeFormErr:
		return "FORMERR"
	case RCodeServFail:
		return "SERVFAIL"
	case RCodeNXDomain:
		return "NXDOMAIN"
	case RCodeNotImp:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", uint8(r))
}

const classIN = 1

// Header flag bits.
const (
	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7
)

// RR is a parsed resource record. Data holds the address for A/AAAA and the
// target name for CNAME and NS records.
type RR struct {
	Name string
	Type Type
	TTL  uint32
	Addr netip.Addr
	Data string
}

// Message is a parsed DNS response.
type Message struct {
	ID                 uint16
	Response           bool
	Authoritative      bool
	Truncated          bool
	RecursionAvailable bool
	RCode              RCode
	QName              string
	QType              Type
	Answers            []RR
	Authority          []RR
}

var errMalformed = errors.New("malformed DNS message")

// buildQuery encodes a recursive query with an EDNS(0) OPT record.
func buildQuery(id uint16, name string, qtype Type) ([]byte, error) {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flagRD)
	binary.BigEndian.PutUint16(b[4:], 1)  // QDCOUNT
	binary.BigEndian.PutUint16(b[10:], 1) // ARCOUNT (OPT)
	var err error
	if b, err = appendName(b, name); err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(qtype))
	b = binary.BigEndian.AppendUint16(b, classIN)
	// OPT pseudo-RR: root name, type 41, UDP payload size 1232
	// (the DNS flag day 2020 recommendation), no extended flags.
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(TypeOPT))
	b = binary.BigEndian.AppendUint16(b, 1232)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	return b, nil
}

func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return nil, fmt.Errorf("dns: name %q too long", name)
	}
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("dns: invalid name %q", name)
			}
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	return append(b, 0), nil
}

// readName decodes a possibly compressed name starting at off and returns
// it with the offset just past it.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errMalformed
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			name := strings.Join(labels, ".")
			if len(name) > 253 {
				return "", 0, errMalformed
			}
			return name, end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errMalformed
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 32 {
				return "", 0, errMalformed // compression loop
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
		case l&0xc0 != 0:
			return "", 0, errMalformed // reserved label types
		default:
			if off+1+l > len(msg) {
				return "", 0, errMalformed
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

// parseMessage decodes a response.
func parseMessage(msg []byte) (*Message, error) {
	if len(msg) < 12 {
		return nil, errMalformed
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	m := &Message{
		ID:                 binary.BigEndian.Uint16(msg[0:]),
		Response:           flags&flagQR != 0,
		Authoritative:      flags&flagAA != 0,
		Truncated:          flags&flagTC != 0,
		RecursionAvailable: flags&flagRA != 0,
		RCode:              RCode(flags & 0x0f),
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, next, err := readName(msg, off)
		if err != nil || next+4 > len(msg) {
			return nil, errMalformed
		}
		if i == 0 {
			m.QName = name
			m.QType = Type(binary.BigEndian.Uint16(msg[next:]))
		}
		off = next + 4
	}
	readRRs := func(n int) ([]RR, error) {
		var out []RR
		for i := 0; i < n; i++ {
			name, next, err := readName(msg, off)
			if err != nil || next+10 > len(msg) {
				return nil, errMalformed
			}
			rr := RR{
				Name: name,
				Type: Type(binary.BigEndian.Uint16(msg[next:])),
				TTL:  binary.BigEndian.Uint32(msg[next+4:]),
			}
			rdlen := int(binary.BigEndian.Uint16(msg[next+8:]))
			rdata := next + 10
			if rdata+rdlen > len(msg) {
				return nil, errMalformed
			}
			switch rr.Type {
			case TypeA:
				if rdlen != 4 {
					return nil, errMalformed
				}
				rr.Addr = netip.AddrFrom4([4]byte(msg[rdata : rdata+4]))
			case TypeAAAA:
				if rdlen != 16 {
					return nil, errMalformed
				}
				rr.Addr = netip.AddrFrom16([16]byte(msg[rdata : rdata+16]))
			case TypeCNAME, TypeNS:
				target, _, err := readName(msg, rdata)
				if err != nil {
					return nil, errMalformed
				}
				rr.Data = target
			}
			out = append(out, rr)
			off = rdata + rdlen
		}
		return out, nil
	}
	var err error
	if m.Answers, err = readRRs(an); err != nil {
		return nil, err
	}
	if m.Authority, err = readRRs(ns); err != nil {
		// Some middleboxes mangle the authority section; the answer is
		// what matters.
		m.Authority = nil
	}
	return m, nil
}

// addresses follows the CNAME chain for name within the answer section and
// returns the final name, the chain and the addresses of the given type.
func (m *Message) addresses(name string, qtype Type) (canonical string, chain []string, addrs []netip.Addr) {
	canonical = name
	for hops := 0; hops < 16; hops++ {
		next := ""
		for _, rr := range m.Answers {
			if rr.Type == TypeCNAME && strings.EqualFold(rr.Name, canonical) {
				next = rr.Data
				break
			}
		}
		if next == "" {
			break
		}
		chain = append(chain, next)
		canonical = next
	}
	for _, rr := range m.Answers {
		if rr.Type == qtype && strings.EqualFold(rr.Name, canonical) {
			addrs = append(addrs, rr.Addr)
		}
	}
	return canonical, chain, addrs
}
