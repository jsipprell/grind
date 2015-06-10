// inmemory dns rr db
package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jsipprell/grind/barricade"
	"github.com/miekg/dns"
	"github.com/ryszard/goskiplist/skiplist"
	"golang.org/x/net/context"
)

var (
	ErrCacheNXDOMAIN = errors.New("NXDOMAIN")
)

type RRCacher interface {
	View() *RRCacheView
}

type RR interface {
	Matcher
	RRish
	ZoneString() string
	ExpireAt() time.Time
	dnsRR() dns.RR
	calcTTL() uint32

	Type() uint16
	Class() uint16
	Clone() RR
}

type RRCacheView struct {
	barricade.Barricade

	expList  *skiplist.SkipList
	nameList *skiplist.SkipList

	verbose bool
}

type RRCache struct {
	*RRCacheView

	snapshot    *snapshot
	snapshotCtx context.Context
	sem         chan struct{}
}

type rrec struct {
	dns.RR

	rcode *uint16
	expAt time.Time
	Key   string
}

func (rr *rrec) ExpireAt() time.Time {
	return rr.expAt
}

func (rr *rrec) dnsRR() dns.RR {
	return rr.RR
}

func (rr *rrec) clone() *rrec {
	var rcode *uint16

	if rr.rcode != nil {
		rcode = new(uint16)
		*rcode = *rr.rcode
	}

	rr = &rrec{
		RR:    dns.Copy(rr.RR),
		rcode: rcode,
		expAt: rr.expAt,
		Key:   rr.Key,
	}

	rr.RR.Header().Ttl = rr.calcTTL()
	return rr
}

func (rr *rrec) Clone() RR {
	return rr.clone()
}

func (rr *rrec) calcTTL() uint32 {
	if !rr.expAt.IsZero() {
		var ttl uint32
		when := rr.expAt.Round(time.Second).Sub(time.Now())
		if when < 0 {
			when = 0
		} else {
			ttl = uint32(when/time.Second) + 1
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
			ttl = uint32(when/time.Second) + 1
		}
		rr.RR.Header().Ttl = ttl
	}
	return rr.RR.String()
}

type notifyChan <-chan struct{}

// NB: absolutely not thread safe, only use with appropriate locking/isolation
func (view *RRCacheView) add(key RRish, v interface{}) {
	view.nameList.Set(key.GetRR(), v)
	view.expList.Set(key.GetRR(), v)
}

func (view *RRCacheView) remove(key Matcher) (v interface{}, ok bool) {
	if rrish, rrok := key.(RRish); rrok {
		rr := rrish.GetRR()
		if v, ok = view.nameList.Delete(rr); ok {
			if view.verbose {
				log.Printf("  -- VIEW -- removed '%+v' (namelist)", rr)
			}
			if v != nil {
				if _, ok := view.expList.Delete(rr); ok && view.verbose {
					log.Printf("  -- VIEW -- removed '%+v' (explist)", rr)
				}
			} else {
				if v, ok = view.expList.Delete(rr); ok && view.verbose {
					log.Printf("  -- VIEW -- removed '%+v' (explist)", rr)
				}
			}
		} else if v == nil {
			if v, ok = view.expList.Delete(rr); ok {
				log.Printf("  -- VIEW -- removed '%+v' (explist)", rr)
			}
		} else {
			if _, ok := view.expList.Delete(rr); ok {
				log.Printf("  -- VIEW -- removed '%+v' (explist)", rr)
			}
		}
		if view.verbose {
			log.Println("  -- VIEW -- DIRECT REMOVE COMPLETE")
		}
		return
	}

	var count int
	var vk interface{}

	name := strings.ToLower(key.Name())
	vk, v, ok = view.nameList.GetGreaterOrEqual(name)
	i := view.nameList.Seek(name)
	if i == nil {
		return
	}
	defer i.Close()
	for ok := i.Previous(); ok;  ok = i.Previous() {
		if i.Key().(RR).Name() != name {
			i.Next()
			break
		}
	}
	vk,v = i.Key(), i.Value()
	for rr := vk.(RR); rr != nil && rr.Name() == name; rr, v = i.Key().(RR), i.Value() {
		if view.verbose {
			log.Printf("  -- VIEW -- MATCHING REMOVE EXAMINE: key=%q, vk=%+v, v=%+v, ok=%v", name, vk, v, ok)
		}
		if key.Match(rr) {
			var rok bool
			if v, rok = view.nameList.Delete(rr); rok {
				count++
				if view.verbose {
					log.Printf("  -- VIEW -- '%#v' REMOVE MATCH (namelist) '%+v'", key, rr)
				}
			} else if view.verbose {
				log.Printf("  -- VIEW -- WARNING WARNING: '%#v' matched but failed to delete %v", key, rr)
			}
			if _, rok = view.expList.Delete(rr); rok && view.verbose {
				log.Printf("  -- VIEW -- '%#v' REMOVE MATCH (explist) '%+v'", key, rr)
			}
		} else if view.verbose {
			log.Printf("  -- VIEW -- NOMATCH '%#v' doesn't match '%+v'", key, rr)
		}
		if ok = i.Next(); !ok {
			break
		}
	}

	ok = count > 0
	return
}

func (view *RRCacheView) lookup(includeGlue bool, matching ...Matcher) []RR {
	var notify []notifyChan

	rrseen := make(map[dns.RR]struct{})
	gluerecs := make(map[string]struct{})
	result := make([]RR, 0, 1)
	i := view.nameList.Iterator()
	defer i.Close()
	matchingQ := NewQueue(len(matching))
	defer matchingQ.Cancel()
	for _, m := range matching {
		matchingQ.Push(m)
	}

	for nextMatcher := range matchingQ.C {
		m, _ := nextMatcher().(Matcher)
		for m == nil && len(notify) > 0 {
			if ln := len(notify); ln > 0 {
				<-notify[0]
				if ln > 1 {
					copy(notify[:], notify[1:])
					notify[ln-1] = nil
				}
				notify = notify[:ln-1]
			}
			m, _ = nextMatcher().(Matcher)
		}
		if m == nil {
			break
		}
		name := m.Name()
		//log.Printf("   MATCH <%s>", name)
		start, _, ok := view.nameList.GetGreaterOrEqual(name)
		if !ok || !i.Seek(start) {
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
						m.AddMatch(MatchOpTypeSlice, []uint16{dns.TypeA, dns.TypeAAAA})
						m.AddMatch(MatchOpName, nsname)
						notify = append(notify, matchingQ.PushAsync(m))
					}
				} else if rr.Type() == dns.TypeCNAME {
					target := strings.ToLower(dns.Fqdn(rr.dnsRR().(*dns.CNAME).Target))
					if _, ok := gluerecs[target]; !ok {
						gluerecs[target] = struct{}{}
						m := newMatcher(target)
						m.AddMatch(MatchOpTypeSlice, []uint16{dns.TypeA, dns.TypeAAAA, dns.TypePTR, dns.TypeCNAME})
						m.AddMatch(MatchOpName, target)
						notify = append(notify, matchingQ.PushAsync(m))
					}
				}
			} else if name != strings.ToLower(rr.Name()) {
				break
			}
			if !i.Next() {
				break
			}
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
		view.add(rr,z)
	}
}

func cacheViewAdd(view *RRCacheView, r RR, zones ...*Zone) {
	var z *Zone

	if len(zones) > 0 {
		z = zones[0]
	}
	view.add(r,z)
}

func (view *RRCacheView) updateFromRRset(rrset []dns.RR, zones ...*Zone) {
	for _, rr := range rrset {
		cacheViewUpdate(view, newRR(rr), zones...)
	}
}

func (view *RRCacheView) update(vals ...Matcher) {
	defer func() {
		if e := recover(); e != nil {
			log.Fatal(e)
		}
	}()

	for _, v := range vals {
		switch rr := v.(type) {
		case RRish:
			if view.verbose {
				log.Printf("  -- VIEW -- removing '%+v' prior to re-add", v)
			}
			view.remove(v)
			if view.verbose {
				log.Println("  -- VIEW -- removed")
			}
			if rz, ok := rr.(RRWithZone); ok {
				view.add(rr, rz.Zone())
				if view.verbose {
					log.Printf("  -- VIEW -- added '%+v' to zone %v", rr, rz.Zone())
				}
			} else {
				view.add(rr, nil)
				if view.verbose {
					log.Printf("  -- VIEW -- added '%+v'", rr)
				}
			}
			continue
		}
		panic("unsupport cachview key type")
	}
		//_, _ = cacheViewUpdate(view, v)
}

func cacheViewShadowUpdate(shadow RRCacher, view *RRCacheView, v interface{}, zones ...*Zone) ([]RR, []RR) {
	var z *Zone

	srcview := shadow.View()
	L := srcview.RLock()
	defer L.RUnlock()

	i := srcview.nameList.Iterator()
	defer i.Close()
	vi := view.nameList.Iterator()
	if vi != nil {
		defer vi.Close()
	}
	if len(zones) > 0 {
		z = zones[0]
	}

	dellist := make([]RR, 0, 1)
	addlist := make([]RR, 0, 1)
	switch r := v.(type) {
	case Matcher:
		name := strings.ToLower(r.Name())
		start, _, ok := view.nameList.GetGreaterOrEqual(name)
		if ok && vi.Seek(start) {
			tmpdel := make([]RR, 0, 1)
			for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
				if r.Match(rr) {
					tmpdel = append(tmpdel, rr)
					continue
				} else if strings.ToLower(rr.Name()) != name {
					break
				}
				if !i.Next() {
					break
				}
			}
			for _, rr := range tmpdel {
				_, ok = view.remove(rr)
			}
			tmpdel = tmpdel[:0]
		}
		start, _, ok = srcview.nameList.GetGreaterOrEqual(name)
		if ok {
			ok = i.Seek(start)
		}
		if !ok {
			if rr, _ := GetRR(r); rr != nil {
				view.add(rr,z)
				addlist = append(addlist, rr)
			}
			return addlist, dellist
		}
		count := 0
		for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
			if r.Match(rr) {
				count++
				dellist = append(dellist, rr)
				if rr, _ = GetRR(r); rr != nil {
					view.add(rr,z)
					addlist = append(addlist, rr)
				}
			} else if name != strings.ToLower(rr.Name()) {
				if rr, _ = GetRR(r); rr != nil && count == 0 {
					view.add(rr,z)
					addlist = append(addlist, rr)
				}
				break
			}
			if ok = i.Next(); !ok {
				if rr, _ = GetRR(r); rr != nil && count == 0 {
					view.add(rr,z)
					addlist = append(addlist, rr)
				}
				break
			}
		}
	case interface{}:
		panic("bad type")
	}

	return addlist, dellist
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
		name := strings.ToLower(r.Name())
		start, _, ok := view.nameList.GetGreaterOrEqual(name)
		if ok {
			ok = i.Seek(start)
		}

		if !ok {
			if rr, _ := GetRR(r); rr != nil {
				cacheViewAdd(view, rr, zones...)
				addlist = append(addlist, rr)
			}
			return addlist, nil
		}
		count := 0
		for rr, ok := i.Key().(RR); ok; rr, ok = i.Key().(RR) {
			if r.Match(rr) {
				count++
				dellist = append(dellist, rr)
				if rr, _ = GetRR(r); rr != nil {
					dellist = append(dellist, rr)
					addlist = append(addlist, rr)
				}
			} else if name != strings.ToLower(rr.Name()) {
				if rr, _ = GetRR(r); rr != nil && count == 0 {
					dellist = append(dellist, rr)
					addlist = append(addlist, rr)
				}
				break
			}
			if ok = i.Next(); !ok {
				if rr, _ = GetRR(r); rr != nil && count == 0 {
					dellist = append(dellist, rr)
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
		if _, ok := view.remove(rr); ok {
			if view.verbose {
				log.Printf("MERGE: del %+v", rr)
			}
			rdellist = append(rdellist, rr)
		}
	}
	for _, rr := range addlist {
		if view.verbose {
			log.Printf("MERGE: add %+v", rr)
		}
		view.add(rr,z)
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
			if _, ok := view.remove(rr); ok {
				n++
			}
		}
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
			if _, ok := view.remove(rr); ok {
				n++
			}
		}
	case RR:
		if _, ok := view.remove(r); ok {
			n++
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
		if ok {
			rt := r.Class()
			tt := t.Class()
			ok = rt == tt || rt == dns.ClassANY || rt == 0
			tok = tok && (rt == tt && rt != dns.ClassANY)
		}
		if ok && tok {
			ok = CompareRRData(t.dnsRR(), r.RR)
		} else {
			ok = tok
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
	return &rrec{RR: rr}
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
		expList:   skiplist.NewCustomMap(slOrderByExpire),
		nameList:  skiplist.NewCustomMap(slOrderByName),
	}
	view.SetMaxLevel(16)
	return view
}

func NewRRCache(concurrency int) *RRCache {
	cache := &RRCache{
		RRCacheView: &RRCacheView{
			Barricade: barricade.New(concurrency),
			expList:   skiplist.NewCustomMap(slOrderByExpire),
			nameList:  skiplist.NewCustomMap(slOrderByName),
		},
		sem: make(chan struct{}, 1),
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
	upd := snapReqUpd{gate: g}
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

func (cache *RRCache) LookupSafe(qr ...dns.Question) ([]RR, error) {
	L := cache.Barricade.RLock()
	defer L.RUnlock()

	return cache.Lookup(qr...)
}

func (cache *RRCache) Lookup(qr ...dns.Question) ([]RR, error) {

	soaMatchers := make(map[string]Matcher)
	matchers := make([]Matcher, 0, 2)
	for _, q := range qr {
		var m MutableMatcher
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
			if len(labels) > 1 {
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
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypePTR {
				m.AddMatch(MatchOpTypeSlice, []uint16{q.Qtype, dns.TypeCNAME})
				log.Println("MatchOpTypeSlice")
			} else {
				m.AddMatch(MatchOpType, q.Qtype)
			}
		}
		if q.Qclass != 0 {
			m.AddMatch(MatchOpClass, q.Qclass)
		}
		matchers = append(matchers, m)
	}
	results := cache.lookup(true, matchers...)
	if len(results) == 0 {
		//log.Printf("NXDOMAIN: %+v", qr)
		return nil, ErrCacheNXDOMAIN
	}

	for i, rr := range results {
		results[i] = rr.Clone()
	}
	return results, nil
}
