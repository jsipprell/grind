
package main

import (
	"log"
	"time"
	"strings"
	"net"
	"sync/atomic"

	"github.com/miekg/dns"
)

type Forwarder interface {
	dns.Handler
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type forwarder struct {
	c *dns.Client
	forwardTo []string
	i uint32
}

type cachingForwarder struct {
	*forwarder
	cache *RRCache
}

func (f *forwarder) Exchange(m *dns.Msg, target string) (reply *dns.Msg, trtt time.Duration, err error) {
	var rtt time.Duration
	if target == "" {
		for j := 0; j < len(f.forwardTo); j++ {
			offset := int(atomic.AddUint32(&f.i, uint32(1)) % uint32(len(f.forwardTo)))
			target = f.forwardTo[offset]
			reply, rtt, err = f.c.Exchange(m, target)
			trtt += rtt
			if err == nil {
				return
			}
			reply = nil
		}
	} else {
		reply, trtt, err = f.c.Exchange(m, target)
	}
	return
}

func (f *forwarder) serve(r *dns.Msg) (m *dns.Msg, rrset []dns.RR, err error) {
	var rtt time.Duration
	m, rtt, err = f.Exchange(r, "")
	if err != nil {
		m = nil
		return
	}

	_ = rtt
	rrset = make([]dns.RR, 0, len(m.Answer)+len(m.Ns)+len(m.Extra))
	mm := m.Copy()
	rrset = append(rrset, mm.Answer...)
	rrset = append(rrset, mm.Ns...)
	rrset = append(rrset, mm.Extra...)
	return
}

func (f *forwarder) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m, rtt, err := f.Exchange(r,"")
	defer w.WriteMsg(m)

	_ = rtt
	if err != nil {
		m = new(dns.Msg)
		m.SetRcodeFormatError(r)
		log.Println(err)
		return
	}
}

func (f *cachingForwarder) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var rrset []dns.RR
	var err error
	l := f.cache.RLock()
	defer func() {
		if len(rrset) > 0 {
			err := f.cache.Update(rrset...)
			if err != nil {
				panic(err)
			}
			log.Println("forward cache update completed")
		}
	}()
	defer l.RUnlock()
	if rrset, err = f.cache.Lookup(r.Question...); err == nil && len(rrset) > 0 {
		m := new(dns.Msg)
		m.SetReply(r)
		remain := make([]dns.RR, 0, len(rrset))
		for _, rr := range rrset {
			hdr := rr.Header()
			for _, q := range r.Question {
				if strings.ToLower(q.Name) == strings.ToLower(hdr.Name) {
					if q.Qtype == dns.TypeANY || hdr.Rrtype == q.Qtype {
						if q.Qclass == 0 || hdr.Class == q.Qclass {
						  m.Answer = append(m.Answer, dns.Copy(rr))
							continue
						}
					}
				}
				remain = append(remain, rr)
			}
		}
		for _, rr := range remain {
			if rr.Header().Rrtype == dns.TypeNS {
				m.Ns = append(m.Ns, dns.Copy(rr))
				continue
			}
			m.Extra = append(m.Extra, dns.Copy(rr))
		}
		if len(m.Answer) == 0 {
			m.SetRcode(r, dns.RcodeNameError)
		} else {
			defer w.WriteMsg(m)
			rrset = nil
			return
		}
	}
	m, rrset, err := f.serve(r)
	defer w.WriteMsg(m)

	if err != nil {
		m = new(dns.Msg)
		m.SetRcodeFormatError(r)
		log.Println(err)
		return
	}
	return
}

func NewForwarder(netwrk string, addr ...string) (Forwarder, error) {
	for i, a := range addr {
		h, p, e := net.SplitHostPort(a)
		if e != nil || p == "" {
			p = "53"
		}
		addr[i] = net.JoinHostPort(h,p)
	}
	return &forwarder{
		c:&dns.Client{
			Net:netwrk,
		},
		forwardTo:addr,
	}, nil
}

func NewCachingForwarder(cache *RRCache, netwrk string, addr ...string) (Forwarder, error) {
	f, err := NewForwarder(netwrk, addr...)
	if err == nil {
		return &cachingForwarder{
			forwarder:f.(*forwarder),
			cache:cache,
		}, err
	}
	return nil, err
}


