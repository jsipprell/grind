package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jsipprell/env"
	"github.com/miekg/dns"
)

const (
	TAG     = "$Id: 6b295a585201f42ae04f8af5040bfe58a1d96ab4 $"
	VERSION = "0"
)

var (
	ServerConfig = struct {
		Addr       string `env:"key=LISTEN_ADDR default=:53"`
		Forwarders string `env:"key=FORWARDERS default=8.8.8.8:53"`
	}{}
	shutdown chan struct{}
)

func makeDnsRR(name string, rtype uint16, rclass uint16, rr dns.RR) dns.RR {
	hdr := rr.Header()
	if name != "" {
		hdr.Name = name
	}
	if rtype != 0 && rtype != dns.TypeANY {
		hdr.Rrtype = rtype
	}
	if rclass != 0 {
		hdr.Class = rclass
	}
	return rr
}

func setResponse(msg *dns.Msg, req *dns.Msg) *dns.Msg {
	if msg == nil {
		msg = new(dns.Msg)
	}
	if req != nil {
		msg.SetReply(req)
		if req.RecursionDesired {
			msg.RecursionAvailable = true
		}
	}
	return msg
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := setResponse(nil, r)
	defer w.WriteMsg(m)

	log.Printf("RX: %+v", r)
	m.SetRcode(r, dns.RcodeNameError)
}

func getServerDescription() []string {
	var tag string
	lines := make([]string, 2)
	taginfo := strings.Fields(TAG)
	if len(taginfo) == 3 && len(taginfo[1]) > 7 {
		tag = taginfo[1][:7]
	}
	if tag != "" {
		lines[0] = fmt.Sprintf("grind prototype version %v/%v", VERSION, tag)
	} else {
		lines[0] = fmt.Sprintf("grind prototype version %v", VERSION)
	}
	lines[1] = fmt.Sprintf("running on %v-%v, %v", runtime.GOOS, runtime.GOARCH, runtime.Version())
	return lines
}

func reportServerId(w dns.ResponseWriter, r *dns.Msg) {
	m := setResponse(nil, r)
	defer w.WriteMsg(m)

	for _, q := range r.Question {
		if strings.ToLower(q.Name) == "id.server." && (q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY) && (q.Qclass == dns.ClassCHAOS || q.Qclass == dns.ClassANY) {
			t := q.Qtype
			cls := q.Qclass
			if t == dns.TypeANY {
				t = dns.TypeTXT
			}
			if cls == dns.ClassANY {
				cls = dns.ClassCHAOS
			}
			m.Answer = append(m.Answer, makeDnsRR(q.Name, t, cls, &dns.TXT{Txt: getServerDescription()}))
			return
		}
	}
	m.SetRcode(r, dns.RcodeNameError)
}

func startServer(s *dns.Server) error {
	c := make(chan error, 2)
	go func() {
		c <- s.ListenAndServe()
	}()

	select {
	case err := <-c:
		return err
	case <-time.After(10 * time.Millisecond):
		return nil
	}
}

func loadZones(args ...string) {
	for _, zf := range args {
		zone, err := LoadZoneFromFile(zf)
		if err != nil {
			log.Fatal(err)
		}

		zone.AddToCache(CachingMux.Cache)
		log.Printf("LOADED %s", zone.Origin)
	}
}

func init() {
	env.MustProcess(&ServerConfig)
	CachingMux.Cache = NewRRCache(200)
}

func main() {
	loadZones(os.Args[1:]...)
	shutdown = make(chan struct{}, 2)
	udpServer := &dns.Server{Addr: ServerConfig.Addr, Net: "udp", Handler: CachingMux}
	tcpServer := &dns.Server{Addr: ServerConfig.Addr, Net: "tcp", Handler: CachingMux}

	defaultForward, err := NewCachingForwarder(CachingMux.Cache, "udp", strings.Fields(ServerConfig.Forwarders)...)
	if err != nil {
		panic(err)
	}
	CachingMux.HandleFunc("id.server.", reportServerId)
	CachingMux.HandleFunc("local.", handleRequest)
	CachingMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		log.Printf("+FWD %+v", r)
		defaultForward.ServeDNS(w, r)
	})
	if err := startServer(udpServer); err != nil {
		log.Fatal(err)
	}
	if err := tcpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
