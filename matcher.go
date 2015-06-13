package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

const (
	_                   = iota
	MatchOpName MatchOp = iota
	MatchOpLabel
	MatchOpType
	MatchOpClass
	MatchOpRRData
	MatchOpTypeSlice
)

type MatchOp int

type RRish interface {
	GetRR() RR
}

type Labeled interface {
	Name() string
}

type Matcher interface {
	Labeled
	Match(interface{}) bool
	Less(interface{}) bool
}

type MutableMatcher interface {
	Matcher
	AddMatch(MatchOp,interface{})
}

type matchOp struct {
	op    MatchOp
	value interface{}
}

type matcher struct {
	ops  []matchOp
}

type rrMatcher struct {
	RR
	m *matcher
}

type nameMatcher struct {
	*matcher
	name string
}

func (op MatchOp) String() string {
	switch op {
	case MatchOpName:
		return "MatchOpName"
	case MatchOpLabel:
		return "MatchOpLabel"
	case MatchOpType:
		return "MatchOpType"
	case MatchOpClass:
		return "MatchOpClass"
	case MatchOpRRData:
		return "MatchOpRRData"
	case MatchOpTypeSlice:
		return "MatchOpTypeSlice"
	default:
		return "MatchOpABEND"
	}
}

func (rr *rrMatcher) Less(v interface{}) bool {
	return rr.Name() < v.(RR).Name()
}

func (nm *nameMatcher) GoString() string {
	return fmt.Sprintf("<%s: %#v>", nm.name, nm.matcher)
}

func (nm *nameMatcher) Less(v interface{}) bool {
	return nm.name < v.(RR).Name()
}

func newMatcher(v interface{}) MutableMatcher {
	m := &matcher{ops:make([]matchOp, 0, 1)}

	switch t := v.(type) {
	case RR:
		return &rrMatcher{RR:t,m:m}
	case string:
		return &nameMatcher{matcher:m,name:t}
	case fmt.Stringer:
		return &nameMatcher{matcher:m,name:dns.Fqdn(strings.ToLower(t.String()))}
	}
	panic("unsupported matcher type")
}

func newNameMatcher(v interface{}) MutableMatcher {
	m := newMatcher(v)
	m.AddMatch(MatchOpName, m.Name())
	return m
}

// returns a new matcher based on an existing RR that will match as specifically as possible
// based on rr contents (type, class, data, etc) but without requiring exact identity.
func newMatcherFromRR(r RRish) Matcher {
	rr := r.GetRR()
	m := &nameMatcher{
		matcher:&matcher{ops:make([]matchOp, 0, 3)},
		name:rr.Name(),
	}

	m.AddMatch(MatchOpName, rr.Name())
	m.AddMatch(MatchOpType, rr.Type())
	m.AddMatch(MatchOpClass, rr.Class())
	m.AddMatch(MatchOpRRData, rr.dnsRR())
	return m
}

func (m *matcher) AddMatch(op MatchOp, v interface{}) {
	m.ops = append(m.ops, matchOp{op, v})
}

func (m *nameMatcher) Name() string {
	return m.name
}

func (m *rrMatcher) GetRR() RR {
	return m.RR
}

func (m *rrMatcher) Match(v interface{}) bool {
	return m.m.Match(v)
}

func (m *rrMatcher) AddMatch(op MatchOp, v interface{}) {
	m.m.AddMatch(op,v)
}

func (m *matcher) Match(v interface{}) bool {
	var rr RR
	var ok bool
	if rr, ok = v.(RR); ok {
		ok = false
		for _, op := range m.ops {
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
			case MatchOpTypeSlice:
				rrType := rr.Type()
				types := op.value.([]uint16)
				ok = len(types) == 0
				for _, t := range types {
					if rrType == t {
						ok = true
						break
					}
				}
			case MatchOpClass:
				ok = rr.Class() == op.value.(uint16)
			case MatchOpRRData:
				ok = CompareRRData(rr.dnsRR(), op.value.(dns.RR))
			}
			_ = log.Printf
			//log.Printf("%v/%v[%v/%v] got %+v: %v", op.op, op.value, rr.Name(),rr.Type(), v, ok)
			if !ok {
				return ok
			}
		}
	}
	return ok
}

func GetRR(m Matcher) (RR, bool) {
	r, ok := m.(RRish)
	if ok {
		return r.GetRR(), ok
	}
	return nil, ok
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
		// For safety alawys assume SOA record rrdata matches so that only one SOA rec exists at a time
		return true
		//return strings.ToLower(rr.Ns) == strings.ToLower(rr2.(*dns.SOA).Ns)
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
	case *dns.TKEY:
		return rr.Algorithm == rr2.(*dns.TKEY).Algorithm
	case *dns.RKEY:
		return rr.PublicKey == rr2.(*dns.RKEY).PublicKey
	case *dns.TSIG:
		r := rr2.(*dns.TSIG)
		return rr.Algorithm == r.Algorithm
	case *dns.TLSA:
		return rr.Certificate == rr2.(*dns.TLSA).Certificate
	case *dns.TA:
		return rr.KeyTag == rr2.(*dns.TA).KeyTag
	case *dns.UINFO:
		return rr.Uinfo == rr2.(*dns.UINFO).Uinfo
	case *dns.UID:
		return rr.Uid == rr2.(*dns.UID).Uid
	case *dns.SSHFP:
		return rr.FingerPrint == rr2.(*dns.SSHFP).FingerPrint
	case *dns.SPF:
		r := rr2.(*dns.SPF)
		for _, txt1 := range rr.Txt {
			for _, txt2 := range r.Txt {
				if txt1 == txt2 {
					return true
				}
			}
		}
		return false
	}

	unkrr1 := new(dns.RFC3597)
	unkrr2 := new(dns.RFC3597)
	if err := unkrr1.ToRFC3597(rr1); err != nil {
		panic(err)
	}
	if err := unkrr2.ToRFC3597(rr2); err != nil {
		panic(err)
	}

	return strings.ToLower(unkrr1.Rdata) == strings.ToLower(unkrr2.Rdata)
}
