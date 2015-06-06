package main

import (
	"io"
	"os"
	"time"
	"strings"

	"github.com/miekg/dns"
)

type Zone struct {
	Origin string
	Soa *dns.SOA

	// NB: index 0 is always the SOA
	RRs []RR

	filename string
}

// static resource records, always report an expiration time that is equivalent
// to time.Now() + ttl, as well as ignoring any attempts to update ttl
type srrec struct {
	*rrec
	ttl time.Duration
}

type streamNamer interface {
	Name() string
}

func newStaticRR(rr dns.RR) *srrec {
	return &srrec{
		rrec:&rrec{RR:rr},
		ttl:time.Duration(rr.Header().Ttl) * time.Second,
	}
}

func (rr *srrec) ExpireAt() time.Time {
	return time.Now().Add(rr.ttl)
}

func (rr *srrec) calcTTL() uint32 {
	return uint32(rr.ttl / time.Second)
}

func (z *Zone) AddToCache(cacher RRCacher) {
	view := cacher.View()
	view.WLock()
	defer view.WUnlock()
	cacheViewAddSet(view, z.RRs, z)
}

func LoadZone(r io.Reader) (*Zone, error) {
	var name string
	var err error
	if namer, ok := r.(streamNamer); ok {
		name = namer.Name()
	}
	C := dns.ParseZone(r, "", name)
	zone := &Zone{
		filename:name,
		RRs:make([]RR, 0, 1),
	}

	for token := range C {
		if err != nil {
			continue
		}
		if token.Error != nil {
			err = token.Error
			continue
		}
		rr := newStaticRR(token.RR)
		if rr.Type() == dns.TypeSOA {
			zone.Soa = rr.dnsRR().(*dns.SOA)
			zone.RRs = append(zone.RRs,rr)
			copy(zone.RRs[1:], zone.RRs)
			zone.RRs[0] = rr
			if zone.Origin == "" {
				zone.Origin = strings.ToLower(dns.Fqdn(rr.Name()))
			}
		} else {
			zone.RRs = append(zone.RRs,rr)
		}
	}
	if closer, ok := r.(io.ReadCloser); ok {
		closer.Close()
	}
	if err != nil {
		return nil, err
	}
	return zone, err
}

func LoadZoneFromFile(fname string) (*Zone, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}

	return LoadZone(f)
}
