package main

import (
	"github.com/miekg/dns"
)

type Zone struct {
	Soa *dns.SOA
	RRs []*RR
}
