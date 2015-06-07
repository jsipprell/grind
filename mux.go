// caching muxer

package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

var (
	CachingMux *Mux = &Mux{ServeMux: dns.NewServeMux()}

	// local errors
	muxErrNXDOMAIN = errors.New("NXDOMAIN")
	muxErrIgnore   = errors.New("ignore")
)

type muxErrFromRRCode uint16

type Mux struct {
	*dns.ServeMux
	Cache *RRCache
}

func (e muxErrFromRRCode) Error() string {
	return fmt.Sprintf("rrcode %v", uint16(e))
}

func (mux *Mux) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Printf("MUX: %+v", r.Question)
	if mux.Cache != nil {
		err := mux.serveFromCache(w, r)
		if err != nil {
			log.Printf("MUX: %+v: %v", r.Question, err)
		}
		if err != nil {
			if err == muxErrIgnore {
				return
			}
			if err == muxErrNXDOMAIN || err == ErrCacheNXDOMAIN {
				m := new(dns.Msg)
				m.SetReply(r)
				m.SetRcode(r, dns.RcodeNameError)
				defer w.WriteMsg(m)
				return
			}
			if i, ok := err.(muxErrFromRRCode); ok {
				m := new(dns.Msg)
				m.SetReply(r)
				m.SetRcode(r, int(i))
				defer w.WriteMsg(m)
				return
			}
			log.Printf("unexpected error: %v", err)
			return
		}
	}

	mux.ServeMux.ServeDNS(w, r)
}

func (mux *Mux) postCacheLookupFailure(m *dns.Msg, w dns.ResponseWriter, r *dns.Msg, rrs ...RR) error {
	// decide if this is a legit NXDOMAIN by seeing if we have an authoritative zone the request
	// should fall under
	qnames := make(map[string]uint16)

	for _, q := range r.Question {
		qnames[strings.ToLower(q.Name)] = q.Qtype
	}

	for _, rr := range rrs {
		if rr.Type() != dns.TypeSOA {
			continue
		}
		for qn, qt := range qnames {
			if qt != dns.TypeSOA && dns.CompareDomainName(qn, rr.Name()) > 0 {
				if rrz, ok := rr.(RRWithZone); ok {
					if z := rrz.Zone(); z != nil && z.IsAuthoritative() {
						// send the SOA as a hint of authority
						if len(m.Ns) > 0 {
							m.Ns = m.Ns[:1]
							m.Ns[0] = rr.dnsRR()
						} else {
							m.Ns = append(m.Ns, rr.dnsRR())
						}
						if len(m.Extra) > 0 {
							m.Extra = m.Extra[:0]
						}
						return muxErrNXDOMAIN
					}
				}
			}
		}
	}

	// nothing so far, lookup all possible root soa records in the cache and see
	// if any are authoritative.
	matchers := make([]Matcher, 0, 3)
	for qn, _ := range qnames {
		if labels := dns.Split(qn); len(labels) > 1 {
			for l := range labels[1:] {
				n := qn[l:]
				if n == "" || n == "." {
					continue
				}
				n = dns.Fqdn(n)
				m := newMatcher(n)
				m.AddMatch(MatchOpType, dns.TypeSOA)
				m.AddMatch(MatchOpName, n)
				matchers = append(matchers, m)
			}
		}
	}

	if len(matchers) > 0 {
		for _, rr := range mux.Cache.lookup(false, matchers...) {
			if rrz, ok := rr.(RRWithZone); ok {
				if z := rrz.Zone(); z != nil && z.IsAuthoritative() {
					// send the SOA as a hint of authority
					if len(m.Ns) > 0 {
						m.Ns = m.Ns[:1]
						m.Ns[0] = rr.dnsRR()
					} else {
						m.Ns = append(m.Ns, rr.dnsRR())
					}
					if len(m.Extra) > 0 {
						m.Extra = m.Extra[:0]
					}
					return muxErrNXDOMAIN
				}
			}
		}
	}

	return nil
}

func (mux *Mux) serveFromCache(w dns.ResponseWriter, r *dns.Msg) (err error) {
	var rrset, remain []RR
	var complete bool
	l := mux.Cache.RLock()
	defer l.RUnlock()
	m := new(dns.Msg)
	m.SetReply(r)

	if rrset, err = mux.Cache.Lookup(r.Question...); err == nil && len(rrset) > 0 {
		var qtypeHasNS bool
		remain = make([]RR, 0, len(rrset))
	serveFromCacheNextRR:
		for _, rr := range rrset {
			rrtype := rr.Type()
			rrclass := rr.Class()
			rrname := strings.ToLower(rr.Name())
			for _, q := range r.Question {
				if q.Qtype == dns.TypeNS {
					qtypeHasNS = true
				}
				if strings.ToLower(q.Name) == rrname {
					typeMatch := q.Qtype == dns.TypeANY || rrtype == q.Qtype
					if typeMatch {
						if q.Qclass == 0 || rrclass == q.Qclass {
							m.Answer = append(m.Answer, rr.dnsRR())
							continue serveFromCacheNextRR
						}
					}
				}
			}
			remain = append(remain, rr)
		}
		for _, rr := range remain {
			if !qtypeHasNS && rr.Type() == dns.TypeNS {
				m.Ns = append(m.Ns, rr.dnsRR())
				continue
			}
			m.Extra = append(m.Extra, rr.dnsRR())
		}
	}
	if (err == nil || err == ErrCacheNXDOMAIN) && len(m.Answer) == 0 && len(rrset) > 0 {
		complete = mux.resolveAliases(m, w, r, rrset...)
	}
	if !complete || err == ErrCacheNXDOMAIN {
		err = mux.postCacheLookupFailure(m, w, r, remain...)
		switch err {
		case muxErrNXDOMAIN:
			m.SetRcode(r, dns.RcodeNameError)
			defer w.WriteMsg(m)
			err = muxErrIgnore
		}
	} else if err == nil || complete {
		defer w.WriteMsg(m)
		err = muxErrIgnore
	}

	return
}

func resolveAlias(label string, rrset ...RR) (target string, ok bool) {
	for _, rr := range rrset {
		if rr.Name() == label {
			ok = true
			if rr.Type() == dns.TypeCNAME {
				target = strings.ToLower(dns.Fqdn(rr.dnsRR().(*dns.CNAME).Target))
				break
			}
		}
	}
	return
}

func (mux *Mux) resolveAliases(m *dns.Msg, w dns.ResponseWriter, r *dns.Msg, rrset ...RR) bool {
	var ok bool
	var target string

	cnames := make(map[RR]string)
	loopcheck := make(map[string]struct{})

	for _, rr := range rrset {
		if rr.Type() == dns.TypeCNAME {
			name := rr.Name()
			if _, ok = loopcheck[name]; !ok {
				loopcheck[name] = struct{}{}
				cnames[rr] = strings.ToLower(dns.Fqdn(rr.dnsRR().(*dns.CNAME).Target))
			}
		}
	}
	pending := len(cnames)
	for pending > 0 {
		for rr, cn := range cnames {
			if cn == "" {
				pending--
			} else {
				log.Printf("CNAME %v TARGET: %q", rr.Name(), cn)
				if target, ok = resolveAlias(cn, rrset...); !ok {
					pending--
				} else {
					if _, ok := loopcheck[target]; ok {
						pending--
					} else {
						cnames[rr] = target
						if target != "" {
							loopcheck[target] = struct{}{}
						}
					}
				}
			}
		}
	}

	for rr, cn := range cnames {
		log.Printf("CNAME: %v -> %v", rr.Name(), cn)
		if cn != "" {
			return false
		}
	}
	log.Println("SERVED BY CACHE: COMPLETE")
	return len(cnames) > 0
}
