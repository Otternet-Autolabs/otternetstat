package network

import (
	"context"
	"log"
	"net"
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
	mu        sync.RWMutex
	ifaceName string
	iface     *net.Interface
	devices   map[string]*Device // keyed by IP
	dns       []DNSResult
	internet  []InternetProbe
	issues    []Issue
	history   []HistoryPoint
	gateway   string
	subnet    string
	serverIP  string
	hub       Broadcaster
}

func NewMonitor(ifaceName string, hub Broadcaster) *Monitor {
	return &Monitor{
		ifaceName: ifaceName,
		devices:   make(map[string]*Device),
		hub:       hub,
	}
}

func (m *Monitor) Start(ctx context.Context) {
	m.resolveIface()
	m.detectNetwork()

	// Initial full scan immediately
	m.runScan(ctx)

	scanTicker := time.NewTicker(30 * time.Second)
	probeTicker := time.NewTicker(10 * time.Second)
	histTicker := time.NewTicker(5 * time.Minute)
	defer scanTicker.Stop()
	defer probeTicker.Stop()
	defer histTicker.Stop()

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
	found := arpScan(ctx, m.iface)
	m.mu.Lock()
	now := time.Now()
	seen := make(map[string]bool)
	for _, d := range found {
		seen[d.IP] = true
		if existing, ok := m.devices[d.IP]; ok {
			existing.MAC = d.MAC
			existing.LastSeen = now
			if d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if d.Vendor != "" {
				existing.Vendor = d.Vendor
			}
		} else {
			d.FirstSeen = now
			d.LastSeen = now
			m.devices[d.IP] = d
		}
	}
	// Mark devices not seen recently as offline
	for ip, dev := range m.devices {
		if !seen[ip] && time.Since(dev.LastSeen) > 2*time.Minute {
			dev.Status = StatusOffline
		}
	}
	m.mu.Unlock()
	log.Printf("ARP scan complete: %d devices found", len(found))
	m.runProbes(ctx)
	m.evaluateIssues()
	m.broadcast()
}

func (m *Monitor) runProbes(ctx context.Context) {
	dns := probeDNS(ctx)
	internet := probeInternet(ctx)
	m.mu.Lock()
	m.dns = dns
	m.internet = internet
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
		devs = append(devs, *d)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].IP < devs[j].IP })
	return Snapshot{
		Timestamp: time.Now(),
		Devices:   devs,
		DNS:       append([]DNSResult{}, m.dns...),
		Internet:  append([]InternetProbe{}, m.internet...),
		Issues:    append([]Issue{}, m.issues...),
		ServerIP:  m.serverIP,
		Gateway:   m.gateway,
		Subnet:    m.subnet,
	}
}

func (m *Monitor) History() []HistoryPoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]HistoryPoint{}, m.history...)
}

func (m *Monitor) TriggerScan() {
	m.runScan(context.Background())
}

func (m *Monitor) broadcast() {
	snap := m.Snapshot()
	msg := encodeJSON(map[string]interface{}{
		"type": "snapshot",
		"data": snap,
	})
	m.hub.Broadcast(msg)
}
