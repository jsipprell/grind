package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ryszard/goskiplist/skiplist"
)

func testNewRR(t *testing.T, f string, args ...interface{}) *RR {
	rr, err := dns.NewRR(fmt.Sprintf(f, args...))
	if err != nil {
		t.Fatal(err)
	}
	return newRR(rr)
}

func dumpSkipList(t *testing.T, sl *skiplist.SkipList) {
	i := sl.SeekToFirst()
	if i == nil {
		return
	}
	count := 1
	defer i.Close()
	for ok := true; ok; ok = i.Next() {
		rr, _ := i.Key().(*RR)
		zone, _ := i.Value().(*Zone)
		t.Logf("%d: %s   (%v)", count, rr.ZoneString(), zone)
		count++
	}
}

func seekSkipList(t *testing.T, sl *skiplist.SkipList, seekTo interface{}) {
	i := sl.Seek(seekTo)
	if i == nil {
		t.Fatalf("cannot seek to %v", seekTo)
	}
	count := 1
	defer i.Close()

	for ok := true; ok; ok = i.Next() {
		rr, _ := i.Key().(*RR)
		zone, _ := i.Value().(*Zone)
		t.Logf("%d: %s   (%v)", count, rr.ZoneString(), zone)
		count++
	}
}

func TestRRCacheView(t *testing.T) {
	view := newRRCacheView()
	dumpSkipList(t, view.expList)
	rr := testNewRR(t, "testies. IN 12 A 10.11.12.13")
	cacheViewAdd(view, rr)
	rr = testNewRR(t, "testies. IN 22 MX 10 mail.testies.")
	cacheViewAdd(view, rr)
	rr = testNewRR(t, "mail.testies. IN 8 A 192.168.70.1")
	t.Logf("%#v", rr.RR)
	cacheViewAdd(view, rr)
	time.Sleep(1000 * time.Millisecond)
	dumpSkipList(t, view.expList)
	t.Log("seeking to 'testies.'")
	seekSkipList(t, view.nameList, "testies.")
}
