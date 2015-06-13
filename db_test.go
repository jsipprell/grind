package main

import (
	"testing"
	"strings"
	"time"
	"net"
	"io"

	"github.com/miekg/dns"
	"github.com/jsipprell/grind/db"
)

type testRR struct {
	*rrec
}

func testdnsrr(name string, rrtype uint16, ttl uint32, drr dns.RR) RR {
	drr.Header().Name = strings.ToLower(dns.Fqdn(name))
	drr.Header().Ttl = ttl
	drr.Header().Rrtype = rrtype
	drr.Header().Class = dns.ClassINET
	return newRR(drr)
}

func testmkrr(name string, rrtype uint16, ttl uint32, drr dns.RR) *testRR {
	return &testRR{testdnsrr(name,rrtype,ttl,drr).(*rrec)}
}

func testmkstore() (*db.Store, *db.TTLStore) {
	ss, ttl := db.NewStore(), db.NewTTLStore()

	rr := testmkrr("a.", dns.TypeCNAME, uint32(22), &dns.CNAME{Target: "foo.bar."})

	ss.Add(rr)
	ttl.Add(rr)

	rr = testmkrr("d.b.", dns.TypeA, uint32(5), &dns.A{A:net.ParseIP("13.12.11.10")})
	ss.Add(rr)
	ttl.Add(rr)

	rr = testmkrr("a.b.", dns.TypePTR, uint32(3), &dns.PTR{Ptr: "foo.bar."})
	ss.Add(rr)
	ttl.Add(rr)

	rr = testmkrr("zebra.b.", dns.TypeCNAME, uint32(4), &dns.CNAME{Target:"cheese."})
	ss.Add(rr)
	ttl.Add(rr)

	rr = testmkrr("c.b.", dns.TypePTR, uint32(22), &dns.PTR{Ptr:"cheese.c.b."})
	ss.Add(rr)
	ttl.Add(rr)

	rr = testmkrr("d.b.", dns.TypeA, uint32(4), &dns.A{A:net.ParseIP("10.11.12.13")})
	ss.Add(rr)
	ttl.Add(rr)

	return ss, ttl
}

func (rr *testRR) Less(other interface{}) bool {
	return strings.ToLower(rr.Name()) < strings.ToLower(other.(Labeled).Name())
}

func (rr *testRR) Equal(other interface{}) bool {
	return rr == other
}

func testDumpTTLs(t *testing.T, store *db.TTLStore) {
	now := time.Now()
	i := store.SeekFirst()
	defer i.Close()

	for n, ok := i.Next(); ok; n, ok = i.Next() {
		rr := n.(RR)
		ttl := rr.ExpireAt().Sub(now)
		t.Logf("TTL:%v %+v", ttl, rr)
	}
	if err := i.Err(); err != nil && err != io.EOF {
		t.Fatal(err)
	}
}


func TestStoreLabelBase(t *testing.T) {
	nameList, expList := testmkstore()

	t.Logf("nameList = %+v [len:%d]", nameList,nameList.Len())
	t.Logf("expList = %+v [len:%d]", expList,expList.Len())
	i := nameList.SeekFirst()
	defer i.Close()
	for n, ok := i.Next(); ok && i.Err() == nil; n, ok = i.Next() {
		t.Logf("%v/GOT %+v",ok,  n)
	}

	testDumpTTLs(t, expList)
}

func TestStoreFindLabel(t *testing.T) {
	nameList, expList := testmkstore()

	t.Logf("nameList = %+v [len:%d]", nameList,nameList.Len())
	t.Logf("expList = %+v [len:%d]", expList,expList.Len())

	i := nameList.Find(newNameMatcher("d.b."))
	defer i.Close()
	for n, ok := i.Next(); ok && i.Err() == nil; n, ok = i.Next() {
		t.Logf("FOUND: %v", n)
	}

	testDumpTTLs(t, expList)
}

func TestStoreDeleteRR(t *testing.T) {
	nameList, expList := testmkstore()

	item, ok := nameList.Delete(testdnsrr("d.b.", dns.TypeA, 0, &dns.A{A:net.ParseIP("13.12.11.11")}).(*rrec))
	if ok {
		t.Fatalf("unexpected deletion of %v", item)
	}
	item, ok = nameList.Delete(testdnsrr("d.b.", dns.TypeA, 0, &dns.A{A:net.ParseIP("13.12.11.10")}).(*rrec))
	if !ok {
		t.Fatal("cannot delete A resource record")
	}

	t.Logf("deleted: %v", item.(RREqualing))

	expList.Delete(item.(RREqualing))
	testDumpTTLs(t, expList)
}
