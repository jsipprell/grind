// inmemory dns rr db
package main

import (
	"strings"
	"time"

	"github.com/ryszard/goskiplist/skiplist"
	"github.com/miekg/dns"
)

type RRCacheView struct {
	expList *skiplist.SkipList
	nameList *skiplist.SkipList
}

type RRCache struct {
	expList *skiplist.SkipList
	nameList *skiplist.SkipList
}

type RR struct {
	dns.RR

	rcode *uint16
	ExpireAt time.Time
	Key string
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

func slOrderByName(l, r interface{}) bool {
	return l.(*RR).Name() < r.(*RR).Name()
}

func NewRRCache() *RRCache {
	return &RRCache{
		expList: skiplist.NewCustomMap(slOrderByExpire),
		nameList: skiplist.NewCustomMap(slOrderByName),
	}
}

