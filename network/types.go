package network

import "time"

// DeviceStatus is the connectivity state for a discovered LAN device.
type DeviceStatus string

const (
	StatusOnline      DeviceStatus = "online"      // internet reachable from server + seen on LAN
	StatusLANOnly     DeviceStatus = "lan_only"     // on LAN but internet probe failed
	StatusOffline     DeviceStatus = "offline"      // was seen, now gone
)

// Device represents a device discovered on the LAN.
type Device struct {
	IP           string       `json:"ip"`
	MAC          string       `json:"mac"`
	Hostname     string       `json:"hostname"`
	Vendor       string       `json:"vendor"`
	Status       DeviceStatus `json:"status"`
	LastSeen     time.Time    `json:"last_seen"`
	FirstSeen    time.Time    `json:"first_seen"`
	RTT          int64        `json:"rtt_ms"`  // last ping RTT in ms, -1 = unreachable
	OpenPorts    []int        `json:"open_ports,omitempty"`
}

// DNSResult is the result of a DNS probe against one resolver.
type DNSResult struct {
	Resolver    string  `json:"resolver"`
	Latency     int64   `json:"latency_ms"`
	Success     bool    `json:"success"`
	Error       string  `json:"error,omitempty"`
}

// InternetProbe is the result of an internet reachability check.
type InternetProbe struct {
	Target    string `json:"target"`
	Latency   int64  `json:"latency_ms"`
	Success   bool   `json:"success"`
	Method    string `json:"method"` // "icmp" or "http"
}

// Issue represents a detected network problem with a suggested fix.
type Issue struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // "error", "warning", "info"
	Title       string `json:"title"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

// Snapshot is the full network state broadcast to clients.
type Snapshot struct {
	Timestamp      time.Time       `json:"timestamp"`
	Devices        []Device        `json:"devices"`
	DNS            []DNSResult     `json:"dns"`
	Internet       []InternetProbe `json:"internet"`
	Issues         []Issue         `json:"issues"`
	ServerIP       string          `json:"server_ip"`
	Gateway        string          `json:"gateway"`
	Subnet         string          `json:"subnet"`
	DHCPLeaseCount int             `json:"dhcp_lease_count"`
	DHCPPoolSize   int             `json:"dhcp_pool_size"`
}

// HistoryPoint is a time-series data point for graphing.
type HistoryPoint struct {
	Time       time.Time `json:"t"`
	DeviceCount int      `json:"devices"`
	AvgLatency int64     `json:"avg_latency_ms"`
	DNSOk      bool      `json:"dns_ok"`
	InternetOk bool      `json:"internet_ok"`
}
