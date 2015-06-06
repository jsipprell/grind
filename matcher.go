package main

import (
	"fmt"
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
	GetRR() *RR
	Type() uint16
	Class() uint16
	Match(interface{}) bool
}

type matchOp struct {
	op MatchOp
	value interface{}
}

type matcher struct {
	*RR

	name *string
	ops []matchOp
}

func newMatcher(v interface{}) *matcher {
	var rr *RR
	var name *string

	switch t := v.(type) {
	case *RR:
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

func (m *matcher) GetRR() *RR {
	return m.RR
}

func (m *matcher) Match(v interface{}) bool {
	if rr, ok := v.(*RR); ok {
		ok = false
		for _,op := range m.ops {
			switch op.op {
			case MatchOpName:
				ok = rr.Name() == op.value.(string)
			case MatchOpType:
				t := op.value.(uint16)
				if t != dns.TypeANY {
					ok = rr.Type() == t
				}
			case MatchOpClass:
				ok = rr.Class() == op.value.(uint16)
			}
			if !ok {
				return ok
			}
		}
	}
	return false
}
