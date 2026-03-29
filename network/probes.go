package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

var dnsResolvers = []string{
	"Router",
	"1.1.1.1",
	"8.8.8.8",
	"9.9.9.9",
}

var internetTargets = []struct {
	name   string
	url    string
	method string
}{
	{"Cloudflare", "https://1.1.1.1", "http"},
	{"Google DNS", "https://8.8.8.8", "http"},
	{"Google", "https://www.google.com", "http"},
	{"Cloudflare DNS", "1.1.1.1:53", "dns"},
}

func probeDNS(ctx context.Context) []DNSResult {
	// Find router/gateway IP for the "Router" resolver entry
	results := make([]DNSResult, 0, len(dnsResolvers))
	for _, r := range dnsResolvers {
		addr := r
		name := r
		if r == "Router" {
			gw := defaultGateway()
			if gw == "" {
				results = append(results, DNSResult{
					Resolver: "Router",
					Success:  false,
					Error:    "could not determine gateway",
				})
				continue
			}
			addr = gw
			name = fmt.Sprintf("Router (%s)", gw)
		}
		results = append(results, queryDNS(ctx, name, addr+":53"))
	}
	return results
}

func queryDNS(ctx context.Context, name, addr string) DNSResult {
	c := &dns.Client{Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	m.RecursionDesired = true

	start := time.Now()
	_, _, err := c.ExchangeContext(ctx, m, addr)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return DNSResult{Resolver: name, Success: false, Error: err.Error(), Latency: latency}
	}
	return DNSResult{Resolver: name, Success: true, Latency: latency}
}

func probeInternet(ctx context.Context) []InternetProbe {
	results := make([]InternetProbe, 0)
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// HTTP probes
	httpTargets := []struct{ name, url string }{
		{"Cloudflare", "https://1.1.1.1"},
		{"Google", "https://www.google.com"},
	}
	for _, t := range httpTargets {
		start := time.Now()
		resp, err := httpClient.Get(t.url)
		latency := time.Since(start).Milliseconds()
		if err == nil {
			resp.Body.Close()
			results = append(results, InternetProbe{Target: t.name, Success: true, Latency: latency, Method: "http"})
		} else {
			results = append(results, InternetProbe{Target: t.name, Success: false, Latency: latency, Method: "http"})
		}
	}

	// DNS probe to external resolver (bypasses local DNS)
	start := time.Now()
	c := &dns.Client{Timeout: 3 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	_, _, err := c.ExchangeContext(ctx, msg, "1.1.1.1:53")
	latency := time.Since(start).Milliseconds()
	results = append(results, InternetProbe{
		Target:  "Cloudflare DNS (1.1.1.1)",
		Success: err == nil,
		Latency: latency,
		Method:  "dns",
	})

	return results
}

func defaultGateway() string {
	// Try to find gateway by parsing route table
	// Simple heuristic: connect to external IP and get local address
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", time.Second)
	if err != nil {
		return ""
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if localAddr == nil {
		return ""
	}
	// Guess gateway as .1 on same /24
	gw := make(net.IP, 4)
	copy(gw, localAddr)
	gw[3] = 1
	return gw.String()
}
