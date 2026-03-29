package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const historyMax = 288 // 24h at 5-min intervals

// Broadcaster is implemented by the WebSocket hub.
type Broadcaster interface {
	Broadcast([]byte)
}

// Monitor runs all network probes and maintains state.
type Monitor struct {
	mu               sync.RWMutex
	ifaceName        string
	iface            *net.Interface
	devices          map[string]*Device
	duplicateIPs     []string
	dns              []DNSResult
	internet         []InternetProbe
	issues           []Issue
	issueLog         []IssueLogEntry
	history          []HistoryPoint
	gateway          string
	gatewayHostname  string
	gatewayRTT       int64
	gatewayReachable bool
	gatewayPorts     []PortResult
	subnet           string
	serverIP         string
	ipv6             bool
	ntpSynced        *bool
	packetLossGW     float64
	publicIP         *PublicIPInfo
	traceroute       []TracerouteHop
	wanDownloadMbps  float64
	lastInternetOk   bool

	alerts   []Alert
	alertsMu sync.Mutex

	storePath string
	store     *StoreData
	storeMu   sync.Mutex

	hub Broadcaster
}

func NewMonitor(ifaceName string, hub Broadcaster, storePath string) *Monitor {
	store, err := LoadStore(storePath)
	if err != nil {
		log.Printf("store load error: %v", err)
		store = &StoreData{Nicknames: make(map[string]string)}
	}
	return &Monitor{
		ifaceName: ifaceName,
		devices:   make(map[string]*Device),
		storePath: storePath,
		store:     store,
		hub:       hub,
	}
}

func (m *Monitor) SetNickname(mac, nickname string) error {
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
	if nickname == "" {
		delete(m.store.Nicknames, mac)
	} else {
		m.store.Nicknames[mac] = nickname
	}
	return m.store.Save(m.storePath)
}

func (m *Monitor) GetNickname(mac string) string {
	if mac == "" {
		return ""
	}
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
	return m.store.Nicknames[mac]
}

func (m *Monitor) Nicknames() map[string]string {
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
	out := make(map[string]string, len(m.store.Nicknames))
	for k, v := range m.store.Nicknames {
		out[k] = v
	}
	return out
}

func (m *Monitor) SetWANSpeed(mbps float64) {
	m.mu.Lock()
	m.wanDownloadMbps = mbps
	m.mu.Unlock()
}

// ServerIP returns the server's primary LAN IP address.
func (m *Monitor) ServerIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.serverIP
}

func (m *Monitor) addAlert(a Alert) {
	a.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	a.Timestamp = time.Now()
	m.alertsMu.Lock()
	defer m.alertsMu.Unlock()
	m.alerts = append(m.alerts, a)
	const maxAlerts = 200
	if len(m.alerts) > maxAlerts {
		m.alerts = m.alerts[len(m.alerts)-maxAlerts:]
	}
}

func (m *Monitor) Alerts() []Alert {
	m.alertsMu.Lock()
	defer m.alertsMu.Unlock()
	return append([]Alert{}, m.alerts...)
}

func (m *Monitor) alertCount() int {
	m.alertsMu.Lock()
	defer m.alertsMu.Unlock()
	return len(m.alerts)
}

func (m *Monitor) Start(ctx context.Context) {
	m.resolveIface()
	m.detectNetwork()
	m.runScan(ctx)

	// Background one-shot goroutines
	go func() {
		info := probePublicIP(ctx)
		m.mu.Lock()
		m.publicIP = info
		m.mu.Unlock()
	}()
	go func() {
		hops := RunTraceroute(ctx)
		m.mu.Lock()
		m.traceroute = hops
		m.mu.Unlock()
	}()
	go func() {
		mbps := ProbeWANSpeed(ctx)
		m.mu.Lock()
		m.wanDownloadMbps = mbps
		m.mu.Unlock()
	}()
	go StartBandwidthCapture(m.ifaceName, m.serverIP)

	scanTicker := time.NewTicker(30 * time.Second)
	probeTicker := time.NewTicker(10 * time.Second)
	histTicker := time.NewTicker(5 * time.Minute)
	slowTicker := time.NewTicker(30 * time.Minute)
	defer scanTicker.Stop()
	defer probeTicker.Stop()
	defer histTicker.Stop()
	defer slowTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			m.runScan(ctx)
		case <-probeTicker.C:
			m.runProbes(ctx)
			m.evaluateIssues()
			m.broadcast()
		case <-histTicker.C:
			m.appendHistory()
		case <-slowTicker.C:
			go func() {
				info := probePublicIP(ctx)
				m.mu.Lock()
				m.publicIP = info
				m.mu.Unlock()
			}()
			go func() {
				mbps := ProbeWANSpeed(ctx)
				m.mu.Lock()
				m.wanDownloadMbps = mbps
				m.mu.Unlock()
			}()
		}
	}
}

func (m *Monitor) resolveIface() {
	if m.ifaceName == "" {
		return
	}
	iface, err := net.InterfaceByName(m.ifaceName)
	if err != nil {
		log.Printf("interface %q not found: %v", m.ifaceName, err)
		return
	}
	m.iface = iface
}

func (m *Monitor) runScan(ctx context.Context) {
	log.Printf("Starting ARP scan...")
	found, dupes := arpScan(ctx, m.iface)

	mdnsCh := make(chan map[string][]string, 1)
	go func() { mdnsCh <- ScanMDNSServices(ctx) }()

	// Vendor lookup via macvendors.com (parallel, cached)
	var wg sync.WaitGroup
	for _, d := range found {
		if d.Vendor == "" && d.MAC != "" {
			wg.Add(1)
			go func(dev *Device) {
				defer wg.Done()
				if v := lookupMACVendor(dev.MAC); v != "" {
					dev.Vendor = v
				}
			}(d)
		}
	}
	wg.Wait()

	mdnsServices := <-mdnsCh

	// SSL cert checks for gateway (443) and https mDNS services
	m.mu.RLock()
	gw := m.gateway
	gwPorts := m.gatewayPorts
	m.mu.RUnlock()
	gwHas443 := false
	for _, p := range gwPorts {
		if p.Port == 443 && p.Open {
			gwHas443 = true
			break
		}
	}
	for _, d := range found {
		if d.IP == gw && gwHas443 {
			go func(ip string) {
				info := CheckCert(ctx, ip)
				m.mu.Lock()
				if dev, ok := m.devices[ip]; ok {
					dev.CertExpiry = info
				}
				m.mu.Unlock()
			}(d.IP)
		}
		for _, svc := range mdnsServices[d.IP] {
			if svc == "HTTPS" {
				go func(ip string) {
					info := CheckCert(ctx, ip)
					m.mu.Lock()
					if dev, ok := m.devices[ip]; ok {
						dev.CertExpiry = info
					}
					m.mu.Unlock()
				}(d.IP)
				break
			}
		}
	}

	m.mu.Lock()
	now := time.Now()
	seen := make(map[string]bool)

	// Collect alerts without holding m.mu later
	var pendingAlerts []Alert

	for _, d := range found {
		seen[d.IP] = true
		if svcs, ok := mdnsServices[d.IP]; ok {
			d.Services = svcs
		}
		if existing, ok := m.devices[d.IP]; ok {
			wasOffline := existing.Status == StatusOffline
			existing.MAC = d.MAC
			existing.LastSeen = now
			existing.RTT = d.RTT
			existing.DuplicateIP = d.DuplicateIP
			if d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if d.Vendor != "" {
				existing.Vendor = d.Vendor
			}
			if len(d.Services) > 0 {
				existing.Services = d.Services
			}
			existing.Status = StatusOnline
			if wasOffline {
				pendingAlerts = append(pendingAlerts, Alert{
					Type:        AlertDeviceOnline,
					Title:       "Device back online",
					Description: fmt.Sprintf("%s (%s) came back online", existing.Hostname, existing.IP),
					DeviceIP:    existing.IP,
					DeviceMAC:   existing.MAC,
				})
			}
		} else {
			d.FirstSeen = now
			d.LastSeen = now
			m.devices[d.IP] = d
			if d.MAC != "" {
				pendingAlerts = append(pendingAlerts, Alert{
					Type:        AlertNewDevice,
					Title:       "New device on network",
					Description: fmt.Sprintf("New device joined: %s (%s) — %s", d.Hostname, d.IP, d.Vendor),
					DeviceIP:    d.IP,
					DeviceMAC:   d.MAC,
				})
			}
		}
	}
	for ip, dev := range m.devices {
		if !seen[ip] && time.Since(dev.LastSeen) > 2*time.Minute && dev.Status != StatusOffline {
			dev.Status = StatusOffline
			pendingAlerts = append(pendingAlerts, Alert{
				Type:        AlertDeviceOffline,
				Title:       "Device went offline",
				Description: fmt.Sprintf("%s (%s) is no longer reachable", dev.Hostname, dev.IP),
				DeviceIP:    dev.IP,
				DeviceMAC:   dev.MAC,
			})
		}
	}
	m.duplicateIPs = dupes
	m.mu.Unlock()

	for _, a := range pendingAlerts {
		m.addAlert(a)
	}

	log.Printf("ARP scan complete: %d devices found, %d duplicate IPs", len(found), len(dupes))
	m.runProbes(ctx)
	m.evaluateIssues()
	m.broadcast()
}

func (m *Monitor) runProbes(ctx context.Context) {
	m.mu.RLock()
	gw := m.gateway
	m.mu.RUnlock()

	var (
		dnsResults   []DNSResult
		internet     []InternetProbe
		gwReachable  bool
		gwRTT        int64
		gwHostname   string
		gwPorts      []PortResult
		gwPacketLoss float64
		ipv6         bool
		ntpSynced    *bool
	)

	var wg sync.WaitGroup
	wg.Add(6)

	go func() { defer wg.Done(); dnsResults = probeDNS(ctx, gw) }()
	go func() { defer wg.Done(); internet = probeInternet(ctx) }()
	go func() {
		defer wg.Done()
		gwReachable, gwRTT, gwHostname, gwPorts = probeGateway(ctx, gw)
	}()
	go func() {
		defer wg.Done()
		if gw != "" {
			gwPacketLoss = probePacketLoss(ctx, gw)
		}
	}()
	go func() { defer wg.Done(); ipv6 = probeIPv6(ctx) }()
	go func() { defer wg.Done(); ntpSynced = probeNTP() }()

	wg.Wait()

	m.mu.Lock()
	m.dns = dnsResults
	m.internet = internet
	m.gatewayReachable = gwReachable
	m.gatewayRTT = gwRTT
	m.gatewayHostname = gwHostname
	m.gatewayPorts = gwPorts
	m.packetLossGW = gwPacketLoss
	m.ipv6 = ipv6
	m.ntpSynced = ntpSynced
	m.mu.Unlock()
}

func (m *Monitor) appendHistory() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var online int
	var totalRTT int64
	var rttCount int
	for _, d := range m.devices {
		if d.Status != StatusOffline {
			online++
			if d.RTT >= 0 {
				totalRTT += d.RTT
				rttCount++
			}
		}
	}
	var avgRTT int64
	if rttCount > 0 {
		avgRTT = totalRTT / int64(rttCount)
	}
	dnsOk := false
	for _, r := range m.dns {
		if r.Success {
			dnsOk = true
			break
		}
	}
	internetOk := false
	for _, r := range m.internet {
		if r.Success {
			internetOk = true
			break
		}
	}
	m.history = append(m.history, HistoryPoint{
		Time:        time.Now(),
		DeviceCount: online,
		AvgLatency:  avgRTT,
		DNSOk:       dnsOk,
		InternetOk:  internetOk,
	})
	if len(m.history) > historyMax {
		m.history = m.history[len(m.history)-historyMax:]
	}
}

func (m *Monitor) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	devs := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		dev := *d
		dev.Nickname = m.GetNickname(d.MAC)
		dev.RxBps, dev.TxBps = GetBandwidth(d.IP)
		devs = append(devs, dev)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].IP < devs[j].IP })
	return Snapshot{
		Timestamp:        time.Now(),
		Devices:          devs,
		DNS:              append([]DNSResult{}, m.dns...),
		Internet:         append([]InternetProbe{}, m.internet...),
		Issues:           append([]Issue{}, m.issues...),
		ServerIP:         m.serverIP,
		Gateway:          m.gateway,
		GatewayHostname:  m.gatewayHostname,
		GatewayRTT:       m.gatewayRTT,
		GatewayReachable: m.gatewayReachable,
		GatewayPorts:     append([]PortResult{}, m.gatewayPorts...),
		Subnet:           m.subnet,
		DuplicateIPs:     append([]string{}, m.duplicateIPs...),
		IPv6:             m.ipv6,
		NTPSynced:        m.ntpSynced,
		PacketLossGW:     m.packetLossGW,
		PublicIP:         m.publicIP,
		Traceroute:       append([]TracerouteHop{}, m.traceroute...),
		AlertCount:       m.alertCount(),
		WANDownloadMbps:  m.wanDownloadMbps,
	}
}

func (m *Monitor) History() []HistoryPoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]HistoryPoint{}, m.history...)
}

func (m *Monitor) IssueLog() []IssueLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]IssueLogEntry{}, m.issueLog...)
}

func (m *Monitor) updateIssueLog(current []Issue) {
	now := time.Now()
	activeIDs := map[string]bool{}
	for _, i := range current {
		activeIDs[i.ID] = true
	}

	var pendingAlerts []Alert

	for idx := range m.issueLog {
		e := &m.issueLog[idx]
		if activeIDs[e.ID] {
			if !e.Active {
				// Re-activation after clearing
				e.OccurrenceCount++
				pendingAlerts = append(pendingAlerts, Alert{
					Type:    AlertIssueAppeared,
					Title:   "Issue recurred: " + e.Title,
					IssueID: e.ID,
				})
			}
			e.LastSeen = now
			e.Active = true
			e.ClearedAt = nil
		} else if e.Active {
			e.Active = false
			t := now
			e.ClearedAt = &t
			pendingAlerts = append(pendingAlerts, Alert{
				Type:    AlertIssueCleared,
				Title:   "Issue resolved: " + e.Title,
				IssueID: e.ID,
			})
		}
	}

	existingIDs := map[string]bool{}
	for _, e := range m.issueLog {
		existingIDs[e.ID] = true
	}
	for _, i := range current {
		if !existingIDs[i.ID] {
			m.issueLog = append(m.issueLog, IssueLogEntry{
				Issue:           i,
				FirstSeen:       now,
				LastSeen:        now,
				Active:          true,
				OccurrenceCount: 1,
			})
			pendingAlerts = append(pendingAlerts, Alert{
				Type:    AlertIssueAppeared,
				Title:   "Issue detected: " + i.Title,
				IssueID: i.ID,
			})
		}
	}

	const maxLog = 500
	if len(m.issueLog) > maxLog {
		m.issueLog = m.issueLog[len(m.issueLog)-maxLog:]
	}

	// Emit after returning — caller must release m.mu first
	// We use a goroutine to avoid deadlock since addAlert uses alertsMu
	go func() {
		for _, a := range pendingAlerts {
			m.addAlert(a)
		}
	}()
}

func (m *Monitor) TriggerScan() {
	m.runScan(context.Background())
	go func() {
		hops := RunTraceroute(context.Background())
		m.mu.Lock()
		m.traceroute = hops
		m.mu.Unlock()
		m.broadcast()
	}()
}

func (m *Monitor) broadcast() {
	snap := m.Snapshot()
	msg, _ := json.Marshal(map[string]interface{}{
		"type": "snapshot",
		"data": snap,
	})
	m.hub.Broadcast(msg)
}

// storePath default: same dir as executable, filename otternetstat.json
func DefaultStorePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "otternetstat.json"
	}
	return filepath.Join(filepath.Dir(exe), "otternetstat.json")
}
