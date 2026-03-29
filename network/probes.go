package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var dnsResolvers = []string{
	"Router",
	"1.1.1.1",
	"8.8.8.8",
	"9.9.9.9",
}

// probeDNS queries all configured resolvers and returns results.
func probeDNS(ctx context.Context, gateway string) []DNSResult {
	results := make([]DNSResult, 0, len(dnsResolvers))
	for _, r := range dnsResolvers {
		addr := r
		name := r
		if r == "Router" {
			gw := gateway
			if gw == "" {
				gw = defaultGateway()
			}
			if gw == "" {
				results = append(results, DNSResult{Resolver: "Router", Success: false, Error: "could not determine gateway"})
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
	resp, _, err := c.ExchangeContext(ctx, m, addr)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return DNSResult{Resolver: name, Success: false, Error: err.Error(), Latency: latency}
	}

	var addrs []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			addrs = append(addrs, a.A.String())
		}
	}
	return DNSResult{Resolver: name, Success: true, Latency: latency, Addresses: addrs}
}

// probeInternet runs HTTP and DNS internet reachability checks.
func probeInternet(ctx context.Context) []InternetProbe {
	results := make([]InternetProbe, 0)
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpTargets := []struct{ name, url string }{
		{"Cloudflare (1.1.1.1)", "https://1.1.1.1"},
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

// probeIPv6 checks if IPv6 internet connectivity is available.
func probeIPv6(ctx context.Context) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipv6.google.com", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// probeGateway pings the gateway and scans common ports.
func probeGateway(ctx context.Context, gateway string) (reachable bool, rtt int64, hostname string, ports []PortResult) {
	if gateway == "" {
		return
	}

	// Ping gateway
	rtt, ok := pingHost(ctx, gateway)
	reachable = ok

	// Reverse DNS
	if names, err := net.LookupAddr(gateway); err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	// Port scan
	portDefs := []struct {
		port    int
		service string
	}{
		{53, "DNS"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{8080, "HTTP-alt"},
		{8443, "HTTPS-alt"},
	}
	portResults := make([]PortResult, len(portDefs))
	done := make(chan struct{}, len(portDefs))
	for i, pd := range portDefs {
		go func(idx, port int, service string) {
			addr := fmt.Sprintf("%s:%d", gateway, port)
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				portResults[idx] = PortResult{Port: port, Open: true, Service: service}
			} else {
				portResults[idx] = PortResult{Port: port, Open: false, Service: service}
			}
			done <- struct{}{}
		}(i, pd.port, pd.service)
	}
	for range portDefs {
		<-done
	}
	ports = portResults
	return
}

// probePacketLoss sends multiple pings and returns the packet loss percentage.
func probePacketLoss(ctx context.Context, target string) float64 {
	count := 5
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "1000", "-t", strconv.Itoa(count+1), target)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "1", target)
	}
	out, err := cmd.Output()
	if err != nil {
		return 100.0
	}
	// Parse "X packets transmitted, Y received, Z% packet loss"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "packet loss") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasSuffix(f, "%") {
					f = strings.TrimSuffix(f, "%")
					if v, err := strconv.ParseFloat(f, 64); err == nil {
						return v
					}
				}
			}
		}
	}
	return 0
}

// probeNTP checks if NTP is synchronized (Linux only via timedatectl).
func probeNTP() *bool {
	if runtime.GOOS != "linux" {
		return nil
	}
	out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized").Output()
	if err != nil {
		return nil
	}
	synced := strings.TrimSpace(string(out)) == "NTPSynchronized=yes"
	return &synced
}

// detectDNSHijack returns true if resolvers return conflicting IPs for google.com.
func detectDNSHijack(results []DNSResult) bool {
	seen := map[string]bool{}
	sets := 0
	for _, r := range results {
		if !r.Success || len(r.Addresses) == 0 {
			continue
		}
		key := strings.Join(sortedCopy(r.Addresses), ",")
		seen[key] = true
		sets++
	}
	// If we have 2+ successful resolvers and they all agree, no hijack
	// If they return different sets, possible hijack
	return sets >= 2 && len(seen) > 1
}

func sortedCopy(ss []string) []string {
	out := make([]string, len(ss))
	copy(out, ss)
	// Simple bubble sort for small slices
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[i] > out[j] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func defaultGateway() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", time.Second)
	if err != nil {
		return ""
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if localAddr == nil {
		return ""
	}
	gw := make(net.IP, 4)
	copy(gw, localAddr)
	gw[3] = 1
	return gw.String()
}

// ── Public IP info (ip-api.com) ─────────────────────────────────────────────

// probePublicIP fetches public IP metadata from ip-api.com (free, no key required).
func probePublicIP(ctx context.Context) *PublicIPInfo {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://ip-api.com/json/?fields=status,country,regionName,city,isp,org,as,query", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "otternetstat/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}
	var info PublicIPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	if info.IP == "" {
		return nil
	}
	return &info
}

// ── MAC vendor lookup (api.macvendors.com) ──────────────────────────────────

var (
	macVendorCache   = map[string]string{}
	macVendorCacheMu sync.Mutex
)

// lookupMACVendor queries api.macvendors.com for a MAC address vendor name.
// Returns empty string on failure. Results are cached in memory.
func lookupMACVendor(mac string) string {
	if mac == "" {
		return ""
	}
	// Normalise to first 8 chars (OUI) for cache key
	key := strings.ToUpper(strings.ReplaceAll(mac, "-", ":")[:min(8, len(mac))])

	macVendorCacheMu.Lock()
	if v, ok := macVendorCache[key]; ok {
		macVendorCacheMu.Unlock()
		return v
	}
	macVendorCacheMu.Unlock()

	client := &http.Client{Timeout: 3 * time.Second}
	url := "https://api.macvendors.com/" + mac
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		macVendorCacheMu.Lock()
		macVendorCache[key] = ""
		macVendorCacheMu.Unlock()
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}
	vendor := strings.TrimSpace(string(body))

	macVendorCacheMu.Lock()
	macVendorCache[key] = vendor
	macVendorCacheMu.Unlock()
	return vendor
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── mDNS service discovery ──────────────────────────────────────────────────

// mdnsServiceTypes maps mDNS service types to friendly names.
var mdnsServiceTypes = []struct {
	svcType string
	name    string
}{
	{"_airplay._tcp", "AirPlay"},
	{"_raop._tcp", "AirPlay Audio"},
	{"_googlecast._tcp", "Chromecast"},
	{"_smb._tcp", "SMB/Windows Share"},
	{"_afpovertcp._tcp", "AFP/Mac Share"},
	{"_ssh._tcp", "SSH"},
	{"_http._tcp", "HTTP"},
	{"_https._tcp", "HTTPS"},
	{"_ftp._tcp", "FTP"},
	{"_printer._tcp", "Printer"},
	{"_ipp._tcp", "IPP Printer"},
	{"_ipps._tcp", "IPPS Printer"},
	{"_pdl-datastream._tcp", "PDL Printer"},
	{"_homekit._tcp", "HomeKit"},
	{"_hap._tcp", "HomeKit Accessory"},
	{"_matter._tcp", "Matter/Thread"},
	{"_spotify-connect._tcp", "Spotify Connect"},
	{"_daap._tcp", "iTunes/DAAP"},
	{"_nfs._tcp", "NFS"},
	{"_telnet._tcp", "Telnet"},
	{"_workstation._tcp", "Workstation"},
	{"_companion-link._tcp", "Apple Continuity"},
}

// ScanMDNSServices queries the LAN for mDNS/Bonjour services and returns
// a map of IP → []service names.
func ScanMDNSServices(ctx context.Context) map[string][]string {
	result := map[string][]string{}
	var mu sync.Mutex

	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	})
	if err != nil {
		return result
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	conn.SetReadDeadline(deadline)

	// Send PTR queries for each service type
	go func() {
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return
		}
		defer c.Close()
		dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
		for _, svc := range mdnsServiceTypes {
			m := new(dns.Msg)
			m.SetQuestion(svc.svcType+".local.", dns.TypePTR)
			m.RecursionDesired = false
			buf, err := m.Pack()
			if err == nil {
				c.WriteToUDP(buf, dst)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Read responses
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		ip := addr.IP.String()

		// Parse additional/answer records for SRV/A records to find real IPs
		allRecords := append(msg.Answer, msg.Extra...)
		for _, rr := range allRecords {
			if a, ok := rr.(*dns.A); ok {
				ip = a.A.String()
			}
		}

		// Match service names from PTR answers
		for _, rr := range msg.Answer {
			if ptr, ok := rr.(*dns.PTR); ok {
				for _, svc := range mdnsServiceTypes {
					if strings.Contains(strings.ToLower(ptr.Hdr.Name), strings.ToLower(svc.svcType)) {
						mu.Lock()
						services := result[ip]
						found := false
						for _, s := range services {
							if s == svc.name {
								found = true
								break
							}
						}
						if !found {
							result[ip] = append(result[ip], svc.name)
						}
						mu.Unlock()
					}
				}
			}
		}
	}
	return result
}

// ProbeWANSpeed downloads 1MB from Cloudflare and returns speed in Mbps.
func ProbeWANSpeed(ctx context.Context) float64 {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://speed.cloudflare.com/__down?bytes=1000000", nil)
	if err != nil {
		return 0
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n == 0 {
		return 0
	}
	elapsed := time.Since(start).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(n*8) / elapsed / 1e6
}

// unused but kept for reference
var _ = bytes.Compare
