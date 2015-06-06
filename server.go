package main

import (
	"log"
	"time"
	"os"

	"github.com/miekg/dns"
)

var (
	shutdown chan struct{}
	MainCache *RRCache
)

func setResponse(msg *dns.Msg, req *dns.Msg) *dns.Msg {
	if msg == nil  {
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

		zone.AddToCache(MainCache)
		log.Printf("LOADED %s", zone.Origin)
	}
}

func main() {
	MainCache = NewRRCache(200)

	loadZones(os.Args[1:]...)
	shutdown = make(chan struct{}, 2)
	udpServer := &dns.Server{Addr: ":5454", Net: "udp"}
	tcpServer := &dns.Server{Addr: ":5454", Net: "tcp"}

	defaultForward, err := NewCachingForwarder(MainCache,"udp", "localhost")
	if err != nil {
		panic(err)
	}
	dns.HandleFunc("local.", handleRequest)
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		log.Printf("+FWD %+v", r)
		defaultForward.ServeDNS(w,r)
	})
	if err := startServer(udpServer); err != nil {
		log.Fatal(err)
	}
	if err := tcpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
