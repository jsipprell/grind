package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

const (
	_ = iota
	MatchOpName MatchOp = iota
	MatchOpLabel
	MatchOpType
	MatchOpClass
	MatchOpData
)

type MatchOp int

type Matcher interface {
	Name() string
	GetRR() RR
	Type() uint16
	Class() uint16
	Match(interface{}) bool
}

type matchOp struct {
	op MatchOp
	value interface{}
}

type matcher struct {
	RR

	name *string
	ops []matchOp
}

func (op MatchOp) String() string {
	switch op {
	case MatchOpName: return "MatchOpName"
	case MatchOpLabel: return "MatchOpLabel"
	case MatchOpType: return "MatchOpType"
	case MatchOpClass: return "MatchOpClass"
	case MatchOpData: return "MatchOpData"
	default: return "MatchOpABEND"
	}
}

func newMatcher(v interface{}) *matcher {
	var rr RR
	var name *string

	switch t := v.(type) {
	case RR:
		rr = t
	case string:
		name = &t
	case fmt.Stringer:
		s := dns.Fqdn(strings.ToLower(t.String()))
		name = &s
	}
	return &matcher{RR:rr, name: name, ops:make([]matchOp, 0, 1)}
}

func (m *matcher) AddMatch(op MatchOp, v interface{}) {
	m.ops = append(m.ops, matchOp{op, v})
}

func (m *matcher) Name() string {
	if m.name != nil {
		return *m.name
	} else if m.RR != nil {
		return m.RR.Name()
	}

	return ""
}

func (m *matcher) GetRR() RR {
	return m.RR
}

func (m *matcher) Match(v interface{}) bool {
	var rr RR
	var ok bool
	if rr, ok = v.(RR); ok {
		ok = false
		for _,op := range m.ops {
			switch op.op {
			case MatchOpName:
				ok = rr.Name() == op.value.(string)
			case MatchOpType:
				t := op.value.(uint16)
				if t == dns.TypeANY {
					ok = true
				} else {
					ok = rr.Type() == t
				}
			case MatchOpClass:
				ok = rr.Class() == op.value.(uint16)
			}
			_ = log.Printf
			//log.Printf("%v/%v[%v/%v/%v] got %+v: %v", op.op, op.value, m.Name(),rr.Name(),rr.Type(), v, ok)
			if !ok {
				return ok
			}
		}
	}
	return ok
}

// compare rrdata for two RRs.. hdrs must already match
func CompareRRData(rr1, rr2 dns.RR) bool {
	if rr1 == rr2 {
		return true
	}

	if rr1.Header().Rrtype != rr2.Header().Rrtype {
		panic("invalid rrdata comparison")
	}

	switch rr := rr1.(type) {
	case *dns.ANY:
		return true
	case *dns.CNAME:
		return rr.Target == rr2.(*dns.CNAME).Target
	case *dns.HINFO:
		r := rr2.(*dns.HINFO)
		return rr.Cpu == r.Cpu && rr.Os == r.Os
	case *dns.MB:
		return rr.Mb == rr2.(*dns.MB).Mb
	case *dns.MG:
		return rr.Mg == rr2.(*dns.MG).Mg
	case *dns.MINFO:
		r := rr2.(*dns.MINFO)
		return strings.ToLower(rr.Rmail) == strings.ToLower(r.Rmail) && strings.ToLower(rr.Email) == strings.ToLower(r.Email)
	case *dns.MX:
		r := rr2.(*dns.MX)
		return rr.Preference == r.Preference && rr.Mx == r.Mx
	case *dns.NS:
		return strings.ToLower(rr.Ns) == strings.ToLower(rr2.(*dns.NS).Ns)
	case *dns.PTR:
		return strings.ToLower(rr.Ptr) == strings.ToLower(rr2.(*dns.PTR).Ptr)
	case *dns.SOA:
		return strings.ToLower(rr.Ns) == strings.ToLower(rr2.(*dns.SOA).Ns)
	case *dns.TXT:
		r := rr2.(*dns.TXT)
		for _, txt1 := range rr.Txt {
			for _, txt2 := range r.Txt {
				if txt1 == txt2 {
					return true
				}
			}
		}
		return false
	case *dns.SRV:
		r := rr2.(*dns.SRV)
		return strings.ToLower(rr.Target) == strings.ToLower(r.Target) && rr.Port == r.Port
	case *dns.A:
		return rr.A.Equal(rr2.(*dns.A).A)
	case *dns.AAAA:
		return rr.AAAA.Equal(rr2.(*dns.AAAA).AAAA)
	case *dns.DS:
		return rr.KeyTag == rr2.(*dns.DS).KeyTag
	case *dns.DLV:
		return rr.KeyTag == rr2.(*dns.DLV).KeyTag
	case *dns.NSEC:
		return strings.ToLower(rr.NextDomain) == strings.ToLower(rr2.(*dns.NSEC).NextDomain)
	case *dns.RRSIG:
		return rr.KeyTag == rr2.(*dns.RRSIG).KeyTag
	}

	panic("unsupport rrtype")
}
