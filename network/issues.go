package network

import "fmt"

func (m *Monitor) evaluateIssues() {
	m.mu.Lock()
	defer m.mu.Unlock()

	issues := []Issue{}

	// ── Internet connectivity ──────────────────────────────────────────────
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

	// ── Gateway reachability ───────────────────────────────────────────────
	if m.gateway != "" && !m.gatewayReachable {
		issues = append(issues, Issue{
			ID:          "gateway_unreachable",
			Severity:    "error",
			Title:       "Gateway not responding",
			Description: fmt.Sprintf("The router/gateway at %s is not responding to pings. Devices on the LAN cannot reach the internet.", m.gateway),
			Suggestion:  "Check if the router is powered on and not overloaded. Try restarting it.",
		})
	}

	// ── Packet loss to gateway ─────────────────────────────────────────────
	if m.packetLossGW > 0 && m.gatewayReachable {
		sev := "warning"
		if m.packetLossGW >= 20 {
			sev = "error"
		}
		issues = append(issues, Issue{
			ID:          "packet_loss_gateway",
			Severity:    sev,
			Title:       fmt.Sprintf("%.0f%% packet loss to gateway", m.packetLossGW),
			Description: "Packets are being dropped between this server and the router. This causes intermittent connectivity issues.",
			Suggestion:  "Check the network cable or WiFi signal between the server and the router. Try a different port on the switch.",
		})
	}

	// ── DNS checks ────────────────────────────────────────────────────────
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
			Suggestion:  "Change DNS settings in the router's DHCP config to hand out 1.1.1.1 or 8.8.8.8 to all devices.",
		})
	}

	// Slow DNS
	for _, r := range m.dns {
		if r.Success && r.Latency > 500 {
			issues = append(issues, Issue{
				ID:          "dns_slow_" + r.Resolver,
				Severity:    "warning",
				Title:       "Slow DNS: " + r.Resolver,
				Description: fmt.Sprintf("DNS resolver %s is responding slowly (%dms). This makes websites feel slow to load.", r.Resolver, r.Latency),
				Suggestion:  "Switch to a faster DNS provider. Cloudflare (1.1.1.1) and Google (8.8.8.8) are typically fast.",
			})
		}
	}

	// DNS hijack detection
	if detectDNSHijack(m.dns) {
		issues = append(issues, Issue{
			ID:          "dns_hijack",
			Severity:    "warning",
			Title:       "DNS resolvers returning different results",
			Description: "Different DNS resolvers are returning different IP addresses for the same domain. This may indicate DNS hijacking, split-horizon DNS, or a compromised resolver.",
			Suggestion:  "Check your router's DNS settings. If you don't recognize the DNS server, change it to 1.1.1.1 or 8.8.8.8.",
		})
	}

	// ── Duplicate IPs ──────────────────────────────────────────────────────
	if len(m.duplicateIPs) > 0 {
		issues = append(issues, Issue{
			ID:          "duplicate_ip",
			Severity:    "error",
			Title:       fmt.Sprintf("Duplicate IP address conflict (%d IP(s))", len(m.duplicateIPs)),
			Description: fmt.Sprintf("Multiple devices are responding to the same IP address: %v. This causes random connectivity failures for affected devices.", m.duplicateIPs),
			Suggestion:  "Check if any devices have a static IP set that conflicts with the DHCP range. Assign a fixed IP outside the DHCP pool, or set all devices to use DHCP.",
		})
	}

	// ── NTP sync ──────────────────────────────────────────────────────────
	if m.ntpSynced != nil && !*m.ntpSynced {
		issues = append(issues, Issue{
			ID:          "ntp_not_synced",
			Severity:    "warning",
			Title:       "NTP clock not synchronized",
			Description: "The server's clock is not synchronized with a time server. An incorrect clock can cause HTTPS/TLS certificate errors on devices.",
			Suggestion:  "Run: sudo timedatectl set-ntp true — or check that port 123 (UDP) is not blocked by a firewall.",
		})
	}

	// ── Devices with no internet ───────────────────────────────────────────
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
				Title:       fmt.Sprintf("%d device(s) on LAN with no internet", lanOnlyCount),
				Description: "These devices are connected to the LAN but cannot reach the internet, while the server can. They may have incorrect DNS or gateway settings.",
				Suggestion:  "Check per-device DNS and gateway settings. Try forgetting and rejoining the WiFi network on the affected device.",
			})
		}
	}

	// ── SSL certificate expiry ────────────────────────────────────────────
	for _, d := range m.devices {
		if d.CertExpiry == nil {
			continue
		}
		ci := d.CertExpiry
		if ci.Error != "" {
			issues = append(issues, Issue{
				ID:          "cert_error_" + d.IP,
				Severity:    "warning",
				Title:       fmt.Sprintf("TLS cert check failed: %s", d.IP),
				Description: fmt.Sprintf("Could not retrieve TLS certificate from %s: %s", d.IP, ci.Error),
				Suggestion:  "Verify the device is running HTTPS and is reachable. Check for firewall rules blocking port 443.",
			})
		} else if ci.DaysLeft < 0 {
			issues = append(issues, Issue{
				ID:          "cert_expired_" + d.IP,
				Severity:    "error",
				Title:       fmt.Sprintf("TLS cert expired: %s", d.IP),
				Description: fmt.Sprintf("The TLS certificate on %s expired %d days ago (on %s). Clients will see security warnings.", d.IP, -ci.DaysLeft, ci.NotAfter.Format("2006-01-02")),
				Suggestion:  "Renew the certificate on the device. If it's a router or NAS, check its admin panel for certificate management.",
			})
		} else if ci.DaysLeft <= 30 {
			issues = append(issues, Issue{
				ID:          "cert_expiring_" + d.IP,
				Severity:    "warning",
				Title:       fmt.Sprintf("TLS cert expiring soon: %s (%d days)", d.IP, ci.DaysLeft),
				Description: fmt.Sprintf("The TLS certificate on %s expires on %s (%d days remaining).", d.IP, ci.NotAfter.Format("2006-01-02"), ci.DaysLeft),
				Suggestion:  "Renew the certificate before it expires to avoid security warnings.",
			})
		}
	}

	// ── Internet up/down transition alert ─────────────────────────────────
	if internetOk != m.lastInternetOk {
		if internetOk {
			go m.addAlert(Alert{
				Type:  AlertInternetUp,
				Title: "Internet connection restored",
			})
		} else {
			go m.addAlert(Alert{
				Type:  AlertInternetDown,
				Title: "Internet connection lost",
			})
		}
		m.lastInternetOk = internetOk
	}

	// ── High LAN latency ──────────────────────────────────────────────────
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
			Title:       fmt.Sprintf("%d device(s) with high LAN latency (>50ms)", highLatencyCount),
			Description: "High ping times on a LAN usually indicate WiFi interference, weak signal, or a congested access point.",
			Suggestion:  "Check WiFi channel usage with a WiFi analyzer app. Try moving the device closer to the access point or switch to a less congested channel (e.g. 5GHz).",
		})
	}

	m.issues = issues
	m.updateIssueLog(issues)
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}
