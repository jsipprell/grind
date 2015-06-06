// inmemory dns rr db
package main

import (
	"strings"
	"fmt"
	"log"
	"time"
	"errors"

	"golang.org/x/net/context"
	"github.com/jsipprell/grind/barricade"
	"github.com/ryszard/goskiplist/skiplist"
	"github.com/miekg/dns"
)

var (
	ErrCacheNXDOMAIN = errors.New("NXDOMAIN")
)

type RRCacher interface {
	View() *RRCacheView
}

type RR interface {
	Matcher
	ZoneString() string
	ExpireAt() time.Time
	dnsRR() dns.RR
	calcTTL() uint32
}

type RRCacheView struct {
	barricade.Barricade

	expList *skiplist.SkipList
	nameList *skiplist.SkipList

	verbose bool
}

type RRCache struct {
	*RRCacheView

	snapshot *snapshot
	snapshotCtx context.Context
	sem chan struct{}
}

type rrec struct {
	dns.RR

	rcode *uint16
	expAt time.Time
	Key string
}

func (rr *rrec) ExpireAt() time.Time {
	return rr.expAt
}

func (rr *rrec) dnsRR() dns.RR {
	return rr.RR
}

func (rr *rrec) calcTTL() uint32 {
	if !rr.expAt.IsZero() {
		var ttl uint32
		when := rr.expAt.Round(time.Second).Sub(time.Now())
		if when < 0 {
			when = 0
		} else {
			ttl = uint32(when / time.Second)+1
		}
		return ttl
	}
	return rr.Header().Ttl
}

func (rr *rrec) ZoneString() string {
	if !rr.expAt.IsZero() {
		var ttl uint32
		when := rr.expAt.Round(time.Second).Sub(time.Now())
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
func (view *RRCacheView) lookup(includeGlue bool,matching ...Matcher) []RR {
	rrseen := make(map[dns.RR]struct{})
	gluerecs := make(map[string]struct{})
	result := make([]RR, 0, 1)
	i := view.nameList.Iterator()
	defer i.Close()
	matchingC := make(chan Matcher, len(matching))
	for _, m := range matching {
		matchingC <- m
	}
	if len(matchingC) == 0 {
		close(matchingC)
	}
	for m := range matchingC {
		var addl int
		name := m.Name()
		//log.Printf("   MATCH <%s>", name)
		start, _, ok := view.nameList.GetGreaterOrEqual(name)
		if !ok || !i.Seek(start) {
			if len(matchingC) == 0 {
				close(matchingC)
			}
			continue
		}
		for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
			if m.Match(rr) {
				if _, ok := rrseen[rr.dnsRR()]; ok {
					if i.Next() {
						continue
					} else {
						break
					}
				}
				rrseen[rr.dnsRR()] = struct{}{}
				result = append(result, rr)
				if includeGlue && rr.Type() == dns.TypeNS {
					nsname := strings.ToLower(dns.Fqdn(rr.dnsRR().(*dns.NS).Ns))
					if _, ok := gluerecs[nsname]; !ok {
						gluerecs[nsname] = struct{}{}
						m := newMatcher(nsname)
						//log.Println("----> NSNAME ",nsname)
						m.AddMatch(MatchOpType, dns.TypeA)
						m.AddMatch(MatchOpName, nsname)
						matching = append(matching, m)
						waitC := make(chan struct{}, 1)
						go func(c chan struct{}, mc chan<- Matcher, m Matcher) {
							defer close(c)
							mc <- m
						}(waitC, matchingC, m)
						if len(matchingC) < cap(matchingC) {
							<-waitC
						}
						addl++
					}
				}
			} else if name != strings.ToLower(rr.Name()) {
				break
			}
			if !i.Next() {
				break
			}
		}
		if len(matchingC) == 0 {
			close(matchingC)
		}
	}
	return result
}

func (view *RRCacheView) View() *RRCacheView {
	return view
}

func cacheViewAddSet(view *RRCacheView, rrset []RR, zones ...*Zone) {
	var z *Zone
	nzones := len(zones)
	for i, rr := range rrset {
		if i < nzones-1 {
			z = zones[i]
		} else if nzones > 0 {
			z = zones[nzones-1]
		}
		view.expList.Set(rr, z)
		view.nameList.Set(rr, z)
	}
}

func cacheViewAdd(view *RRCacheView, r RR, zones ...*Zone) {
	var z *Zone

	if len(zones) > 0 {
		z = zones[0]
	}
	view.expList.Set(r, z)
	view.nameList.Set(r, z)
}

func (view *RRCacheView) updateFromRRset(rrset []dns.RR, zones ...*Zone) {
	for _, rr := range rrset {
		cacheViewUpdate(view, newRR(rr), zones...)
	}
}

func (view *RRCacheView) update(vals ...interface{}) {
	for _, v := range vals {
		_, _ = cacheViewUpdate(view,v)
	}
}

func cacheViewUpdate(view *RRCacheView, v interface{}, zones ...*Zone) ([]RR, []RR) {
	i := view.nameList.Iterator()
	defer i.Close()
	var z *Zone

	if len(zones) > 0 {
		z = zones[0]
	}

	dellist := make([]RR, 0, 1)
	addlist := make([]RR, 0, 1)
	switch r := v.(type) {
	case Matcher:
		start, _, ok := view.nameList.GetGreaterOrEqual(r.Name())
		if ok {
			ok = i.Seek(start)
		}

		if !ok {
			if rr := r.GetRR(); rr != nil {
				cacheViewAdd(view, rr, zones...)
				addlist = append(addlist, rr)
			}
			return addlist, nil
		}
		count := 0
		name := strings.ToLower(r.Name())
		for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
			if r.Match(rr) {
				count++
				dellist = append(dellist, rr)
				if rr = r.GetRR(); rr != nil {
					addlist = append(addlist, rr)
				}
			} else if name != strings.ToLower(rr.Name()) {
				if rr = r.GetRR(); rr != nil && count == 0 {
					addlist = append(addlist, rr)
				}
				break
			}
			if ok = i.Next(); !ok {
				if rr = r.GetRR(); rr != nil && count == 0 {
					addlist = append(addlist, rr)
				}
				break
			}
		}
	case interface{}:
		panic("bad type")
	}

	rdellist := make([]RR, 0, len(dellist))

	for _, rr := range dellist {
		_, ok1 := view.expList.Delete(rr)
		_, ok2 := view.nameList.Delete(rr)
		if ok1 || ok2 {
			if view.verbose {
				//log.Printf("MERGE: del %+v", rr)
			}
			rdellist = append(rdellist, rr)
		}
	}
	for _, rr := range addlist {
		if view.verbose {
			//log.Printf("MERGE: add %+v", rr)
		}
		view.expList.Set(rr, z)
		view.nameList.Set(rr, z)
	}

	return addlist, rdellist
}

func (view *RRCacheView) del(vals ...interface{}) int {
	var n int

	for _, v := range vals {
		n += cacheViewDel(view, v)
	}
	return n
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
		todel := make([]RR, 0, 1)
		for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
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
	case RR:
		_, ok1 := view.nameList.Delete(r)
		_, ok2 := view.expList.Delete(r)
		if ok1 || ok2 {
			n++
		}
	case Matcher:
		name := r.Name()
		start, _, ok := view.nameList.GetGreaterOrEqual(name)
		if !ok {
			return
		}
		i := view.nameList.Iterator()
		defer i.Close()
		if !i.Seek(start) {
			return
		}
		todel := make([]RR, 0, 1)
		for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
			if r.Match(rr) {
				todel = append(todel, rr)
			} else if name != rr.Name() {
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
	}
	return
}

func (r *rrec) Rcode() uint16 {
	if r.rcode != nil {
		return *r.rcode
	}
	return 0
}

func (r *rrec) Name() string {
	if r.Key == "" {
		r.Key = strings.ToLower(r.Header().Name)
	}
	return r.Key
}

func (r *rrec) Type() uint16 {
	return r.Header().Rrtype
}

func (r *rrec) Class() uint16 {
	return r.Header().Class
}

func (r *rrec) TTL() time.Duration {
	return time.Duration(r.Header().Ttl) * time.Second
}

func (r *rrec) Rdlength() uint16 {
	return r.Header().Rdlength
}

func (r *rrec) GetRR() RR {
	return r
}

func (r *rrec) Match(v interface{}) bool {
	var ok bool
	switch t := v.(type) {
	case RR:
		var tok bool
		if ok = t.Name() == r.Name(); ok {
			rt := r.Type()
			tt := t.Type()
			ok = rt == tt || rt == dns.TypeANY
			tok = rt == tt && rt != dns.TypeANY
		}
		if ok && t.Class() != 0 && r.Class() != 0 {
			ok = t.Class() == r.Class()
			if ok && tok {
				trr, rrr := t.dnsRR(), r.RR
				ok = CompareRRData(trr,rrr)
				//log.Printf("COMPARE %+v %+v: %v", trr, rrr, ok)
			}
		}
	case string:
		ok = t == r.Name()
	case fmt.Stringer:
		ok = strings.ToLower(t.String()) == r.Name()
	case interface{}:
		log.Panicf("unsupported type: %T", v)
	}

	return ok
}

func newRR(rr dns.RR) *rrec {
	exp := time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
	return &rrec{RR: rr, expAt: exp}
}

func newPermRR(rr dns.RR) RR {
	return &rrec{RR:rr}
}

func newRcodeRR(name string, rcode uint16, ttl uint32) RR {
	exp := time.Now().Add(time.Duration(ttl) * time.Second)
	return &rrec{rcode: &rcode, expAt: exp, Key: dns.Fqdn(strings.ToLower(name))}
}

func slOrderByExpire(l, r interface{}) bool {
	left, right := l.(RR).ExpireAt(), r.(RR).ExpireAt()

	return (!left.IsZero() || right.IsZero()) && left.Before(right)
}

func slStr(v interface{}) string {
	switch t := v.(type) {
	case RR:
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

func (view *RRCacheView) SetMaxLevel(level int) {
	view.expList.MaxLevel = level
	view.nameList.MaxLevel = level
}

func (view *RRCacheView) MaxLeveL() int {
	return view.nameList.MaxLevel
}

func newRRCacheView() *RRCacheView {
	view := &RRCacheView{
		Barricade: barricade.New(1),
		expList: skiplist.NewCustomMap(slOrderByExpire),
		nameList: skiplist.NewCustomMap(slOrderByName),
	}
	view.SetMaxLevel(16)
	return view
}

func NewRRCache(concurrency int) *RRCache {
	cache := &RRCache{
		RRCacheView:&RRCacheView{
			Barricade: barricade.New(concurrency),
			expList: skiplist.NewCustomMap(slOrderByExpire),
			nameList: skiplist.NewCustomMap(slOrderByName),
		},
		sem:make(chan struct{},1),
	}
	cache.sem <- struct{}{}
	cache.SetMaxLevel(16)
	return cache
}

func (cache *RRCache) View() *RRCacheView {
	return cache.RRCacheView
}

func (cache *RRCache) Update(rrset ...dns.RR) error {
	var err error
	select {
	case <-cache.sem:
		if cache.snapshotCtx != nil {
			<-cache.snapshotCtx.Done()
		}
		cache.snapshot, cache.snapshotCtx = snapshotStart(nil, cache, cache.sem)
	default:
	}

	select {
	case <-cache.snapshotCtx.Done():
		panic("snapshotter down")
	default:
		break
	}

	g := make(chan error, 2)
	upd := snapReqUpd{gate:g}
	upd.updSet = make([]Matcher, len(rrset))
	for i, rr := range rrset {
		upd.updSet[i] = newMatcher(newRR(rr))
	}
	cache.snapshot.reqUpdCh <- upd

	select {
	case <-cache.snapshotCtx.Done():
		err = cache.snapshotCtx.Err()
	case err = <-g:
	}

	return err
}

func (cache *RRCache) Lookup(qr ...dns.Question) ([]dns.RR, error) {
	L := cache.Barricade.RLock()
	defer L.RUnlock()

	soaMatchers := make(map[string]Matcher)
	matchers := make([]Matcher, 0, 2)
	for _, q := range qr {
		var m *matcher
		name := dns.Fqdn(strings.ToLower(q.Name))
		labels := dns.Split(name)
		if _, ok := soaMatchers[name]; !ok {
			m = newMatcher(name)
			m.AddMatch(MatchOpType, dns.TypeSOA)
			m.AddMatch(MatchOpName, name)
			soaMatchers[name] = m
			matchers = append(matchers, m)
			if q.Qtype == dns.TypeSOA {
				continue
			}
			if len(labels) >  1 {
				parent := name[labels[1]:]
				if _, ok := soaMatchers[parent]; !ok {
					m = newMatcher(parent)
					m.AddMatch(MatchOpType, dns.TypeSOA)
					m.AddMatch(MatchOpName, parent)
					soaMatchers[name] = m
					matchers = append(matchers, m)
				}
			}
		}
		if len(labels) > 1 && q.Qtype != dns.TypeNS {
			parent := name[labels[1]:]
			m = newMatcher(parent)
			m.AddMatch(MatchOpType, dns.TypeNS)
			m.AddMatch(MatchOpName, parent)
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
	results := cache.lookup(true,matchers...)
	if len(results) == 0 {
		//log.Printf("NXDOMAIN: %+v", qr)
		return nil, ErrCacheNXDOMAIN
	}
	rset := make([]dns.RR, len(results))
	for i, rr := range results {
		crr := dns.Copy(rr.dnsRR())
		crr.Header().Ttl = rr.calcTTL()
		rset[i] = crr
	}
	return rset, nil
}

