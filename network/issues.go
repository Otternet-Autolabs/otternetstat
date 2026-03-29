package network

import (
	"encoding/json"
	"fmt"
)

func encodeJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (m *Monitor) evaluateIssues() {
	m.mu.Lock()
	defer m.mu.Unlock()

	issues := []Issue{}

	// Check internet connectivity
	internetOk := false
	for _, p := range m.internet {
		if p.Success {
			internetOk = true
			break
		}
	}
	if !internetOk {
		issues = append(issues, Issue{
			ID:          "no_internet",
			Severity:    "error",
			Title:       "No internet access",
			Description: "This server cannot reach the internet. All HTTP and DNS probes to external servers failed.",
			Suggestion:  "Check the router's WAN connection. Try restarting the router or modem. Check if the ISP has an outage.",
		})
	}

	// Check DNS
	dnsOk := false
	dnsRouterOk := false
	dnsExternalOk := false
	for _, r := range m.dns {
		if r.Success {
			dnsOk = true
			if r.Resolver == "1.1.1.1" || r.Resolver == "8.8.8.8" || r.Resolver == "9.9.9.9" {
				dnsExternalOk = true
			} else {
				dnsRouterOk = true
			}
		}
	}
	if !dnsOk {
		issues = append(issues, Issue{
			ID:          "dns_all_fail",
			Severity:    "error",
			Title:       "DNS resolution failing",
			Description: "All DNS resolvers (router and external) are failing. Devices will see 'no internet' even if the connection is up.",
			Suggestion:  "Restart the router. If the problem persists, manually set DNS on devices to 1.1.1.1 or 8.8.8.8.",
		})
	} else if !dnsRouterOk && dnsExternalOk {
		issues = append(issues, Issue{
			ID:          "dns_router_fail",
			Severity:    "warning",
			Title:       "Router DNS not responding",
			Description: "The router's built-in DNS resolver is not responding, but external DNS works. Devices using the router as DNS may fail.",
			Suggestion:  "Change DNS settings on affected devices or in the router DHCP config to use 1.1.1.1 or 8.8.8.8 instead.",
		})
	}

	// Check DNS latency
	for _, r := range m.dns {
		if r.Success && r.Latency > 500 {
			issues = append(issues, Issue{
				ID:          "dns_slow_" + r.Resolver,
				Severity:    "warning",
				Title:       "Slow DNS: " + r.Resolver,
				Description: "DNS resolver " + r.Resolver + " is responding slowly (" + itoa(r.Latency) + "ms). This can make websites feel slow to load.",
				Suggestion:  "Consider switching to a faster DNS provider. Cloudflare (1.1.1.1) and Google (8.8.8.8) are typically fast.",
			})
		}
	}

	// Check for devices with no internet (if we have internet ourselves)
	if internetOk {
		lanOnlyCount := 0
		for _, d := range m.devices {
			if d.Status == StatusLANOnly {
				lanOnlyCount++
			}
		}
		if lanOnlyCount > 0 {
			issues = append(issues, Issue{
				ID:          "devices_no_internet",
				Severity:    "warning",
				Title:       "Some devices have no internet",
				Description: itoa(int64(lanOnlyCount)) + " device(s) are on the LAN but cannot reach the internet. The server can reach the internet fine.",
				Suggestion:  "These devices may have a static DNS set to a non-working server, or their traffic may be blocked by a firewall rule. Check per-device DNS and gateway settings.",
			})
		}
	}

	// Check high latency devices
	highLatencyCount := 0
	for _, d := range m.devices {
		if d.Status != StatusOffline && d.RTT > 50 {
			highLatencyCount++
		}
	}
	if highLatencyCount > 0 {
		issues = append(issues, Issue{
			ID:          "high_latency",
			Severity:    "info",
			Title:       "High LAN latency on some devices",
			Description: itoa(int64(highLatencyCount)) + " device(s) show high ping response times (>50ms). This may indicate WiFi interference or a weak signal.",
			Suggestion:  "Check WiFi channel usage. Try moving the device closer to the access point or switch to a less congested WiFi channel.",
		})
	}

	m.issues = issues
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}
