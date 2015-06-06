// inmemory dns rr db
package main

import (
	"strings"
	"fmt"
	"time"
	"errors"

	"github.com/jsipprell/grind/barricade"
	"github.com/ryszard/goskiplist/skiplist"
	"github.com/miekg/dns"
)

var (
	ErrCacheNXDOMAIN = errors.New("NXDOMAIN")
)

type RRCacheView struct {
	barricade.Barricade

	expList *skiplist.SkipList
	nameList *skiplist.SkipList
}

type RRCache struct {
	*RRCacheView
}

type RR struct {
	dns.RR

	rcode *uint16
	ExpireAt time.Time
	Key string
}

func (rr *RR) calcTTL() uint32 {
	if !rr.ExpireAt.IsZero() {
		var ttl uint32
		when := rr.ExpireAt.Round(time.Second).Sub(time.Now())
		if when < 0 {
			when = 0
		} else {
			ttl = uint32(when / time.Second)+1
		}
		return ttl
	}
	return rr.Header().Ttl
}

func (rr *RR) ZoneString() string {
	if !rr.ExpireAt.IsZero() {
		var ttl uint32
		when := rr.ExpireAt.Round(time.Second).Sub(time.Now())
		if when < 0 {
			when = 0
		} else {
			ttl = uint32(when / time.Second)+1
		}
		rr.RR.Header().Ttl = ttl
	}
	return rr.RR.String()
}

// NB: absolutely not thread safe, only use with appropriate locking/isolation
func (view *RRCacheView) lookup(matching ...Matcher) []*RR {
	result := make([]*RR, 0, 1)
	i := view.nameList.Iterator()
	defer i.Close()
	for _, m := range matching {
		name := m.Name()
		start, _, ok := view.nameList.GetGreaterOrEqual(name)
		if !ok || !i.Seek(start) {
			continue
		}
		for rr, ok := i.Key().(*RR); ok; rr, ok = i.Key().(*RR) {
			if m.Match(rr) {
				result = append(result, rr)
			} else {
				break
			}
			if !i.Next() {
				break
			}
		}
	}
	return result
}

func cacheViewAdd(view *RRCacheView, r *RR, zones ...*Zone) {
	var z *Zone

	if len(zones) > 0 {
		z = zones[0]
	}
	view.expList.Set(r, z)
	view.nameList.Set(r, z)
}

func cacheViewDel(view *RRCacheView, v interface{}) (n int) {
	switch r := v.(type) {
	case string:
		r = strings.ToLower(r)
		start, _, ok := view.nameList.GetGreaterOrEqual(r)
		if !ok {
			return
		}
		i := view.nameList.Iterator()
		defer i.Close()
		if !i.Seek(start) {
			return
		}
		todel := make([]*RR, 0, 1)
		for rr, ok := i.Key().(*RR); ok; rr, ok = i.Key().(*RR) {
			if rr.Name() == r {
				todel = append(todel, rr)
			} else {
				break
			}
			if !i.Next() {
				break
			}
		}
		for _, rr := range todel {
			_, ok1 := view.nameList.Delete(rr)
			_, ok2 := view.expList.Delete(rr)
			if ok1 || ok2 {
				n++
			}
		}
	case *RR:
		_, ok1 := view.nameList.Delete(r)
		_, ok2 := view.expList.Delete(r)
		if ok1 || ok2 {
			n++
		}
	}
	return
}

func (r *RR) Rcode() uint16 {
	if r.rcode != nil {
		return *r.rcode
	}
	return 0
}

func (r *RR) Name() string {
	if r.Key == "" {
		r.Key = strings.ToLower(r.Header().Name)
	}
	return r.Key
}

func (r *RR) Type() uint16 {
	return r.Header().Rrtype
}

func (r *RR) Class() uint16 {
	return r.Header().Class
}

func (r *RR) TTL() time.Duration {
	return time.Duration(r.Header().Ttl) * time.Second
}

func (r *RR) GetRR() *RR {
	return r
}

func (r *RR) Match(v interface{}) bool {
	var ok bool
	switch t := v.(type) {
	case *RR:
		if ok = t.Name() == r.Name(); ok {
			rt := r.Type()
			tt := t.Type()
			ok = rt == tt || rt == dns.TypeANY || tt == dns.TypeANY
		}
		if ok && t.Class() != 0 && r.Class() != 0 {
			ok = t.Class() == r.Class()
		}
	case string:
		ok = t == r.Name()
	case fmt.Stringer:
		ok = strings.ToLower(t.String()) == r.Name()
	case interface{}:
		panic("unsupported type")
	}

	return ok
}

func newRR(rr dns.RR) *RR {
	exp := time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
	return &RR{RR: rr, ExpireAt: exp}
}

func newPermRR(rr dns.RR) *RR {
	return &RR{RR:rr}
}

func newRcodeRR(name string, rcode uint16, ttl uint32) *RR {
	exp := time.Now().Add(time.Duration(ttl) * time.Second)
	return &RR{rcode: &rcode, ExpireAt: exp, Key: dns.Fqdn(strings.ToLower(name))}
}

func slOrderByExpire(l, r interface{}) bool {
	left, right := l.(*RR).ExpireAt, r.(*RR).ExpireAt

	return (!left.IsZero() || right.IsZero()) && left.Before(right)
}

func slStr(v interface{}) string {
	switch t := v.(type) {
	case *RR:
		return t.Name()
	case string:
		return t
	case fmt.Stringer:
		return strings.ToLower(t.String())
	}
	panic("invalid type")
}

func slOrderByName(l, r interface{}) bool {
	return slStr(l) < slStr(r)
}

func newRRCacheView() *RRCacheView {
	return &RRCacheView{
		Barricade: barricade.New(1),
		expList: skiplist.NewCustomMap(slOrderByExpire),
		nameList: skiplist.NewCustomMap(slOrderByName),
	}
}

func NewRRCache(concurrency int) *RRCache {
	return &RRCache{&RRCacheView{
		Barricade: barricade.New(concurrency),
		expList: skiplist.NewCustomMap(slOrderByExpire),
		nameList: skiplist.NewCustomMap(slOrderByName),
	}}
}

func (cache *RRCache) Lookup(qr ...dns.Question) ([]dns.RR, error) {
	L := cache.Barricade.RLock()
	defer L.RUnlock()

	soaMatchers := make(map[string]Matcher)
	matchers := make([]Matcher, 0, 2)
	for _, q := range qr {
		var m *matcher
		name := dns.Fqdn(strings.ToLower(q.Name))
		if _, ok := soaMatchers[name]; !ok {
			m = newMatcher(&dns.SOA{})
			m.AddMatch(MatchOpType, dns.TypeSOA)
			m.AddMatch(MatchOpName, name)
			soaMatchers[name] = m
			matchers = append(matchers, m)
		}
		m = newMatcher(name)
		m.AddMatch(MatchOpName, name)
		if q.Qtype != dns.TypeANY {
			m.AddMatch(MatchOpType, q.Qtype)
		}
		if q.Qclass != 0 {
			m.AddMatch(MatchOpClass, q.Qclass)
		}
		matchers = append(matchers, m)
	}
	results := cache.lookup(matchers...)
	if len(results) == 0 {
		return nil, ErrCacheNXDOMAIN
	}
	rset := make([]dns.RR, len(results))
	for i, rr := range results {
		crr := dns.Copy(rr.RR)
		crr.Header().Ttl = rr.calcTTL()
		rset[i] = crr
	}
	return rset, nil
}

