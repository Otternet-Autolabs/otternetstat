package network

import "time"

// DeviceStatus is the connectivity state for a discovered LAN device.
type DeviceStatus string

const (
	StatusOnline  DeviceStatus = "online"   // seen on LAN
	StatusLANOnly DeviceStatus = "lan_only" // on LAN but internet probe failed
	StatusOffline DeviceStatus = "offline"  // was seen, now gone
)

// Device represents a device discovered on the LAN.
type Device struct {
	IP          string       `json:"ip"`
	MAC         string       `json:"mac"`
	Hostname    string       `json:"hostname"`
	Nickname    string       `json:"nickname,omitempty"`
	Vendor      string       `json:"vendor"`
	Status      DeviceStatus `json:"status"`
	LastSeen    time.Time    `json:"last_seen"`
	FirstSeen   time.Time    `json:"first_seen"`
	RTT         int64        `json:"rtt_ms"`
	DuplicateIP bool         `json:"duplicate_ip,omitempty"`
	Services    []string     `json:"services,omitempty"`
	RxBps       float64      `json:"rx_bps,omitempty"`
	TxBps       float64      `json:"tx_bps,omitempty"`
	CertExpiry  *CertInfo    `json:"cert_expiry,omitempty"`
}

// CertInfo holds TLS certificate expiry information for a host.
type CertInfo struct {
	Host     string    `json:"host"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	Error    string    `json:"error,omitempty"`
}

// DNSResult is the result of a DNS probe against one resolver.
type DNSResult struct {
	Resolver  string   `json:"resolver"`
	Latency   int64    `json:"latency_ms"`
	Success   bool     `json:"success"`
	Error     string   `json:"error,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

// InternetProbe is the result of an internet reachability check.
type InternetProbe struct {
	Target     string  `json:"target"`
	Latency    int64   `json:"latency_ms"`
	Success    bool    `json:"success"`
	Method     string  `json:"method"`
	PacketLoss float64 `json:"packet_loss_pct,omitempty"`
}

// PortResult is the result of a TCP port probe.
type PortResult struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service"`
}

// TracerouteHop is a single hop in a traceroute.
type TracerouteHop struct {
	Hop      int    `json:"hop"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	RTTMs    int64  `json:"rtt_ms"`
	Timeout  bool   `json:"timeout,omitempty"`
}

// Issue represents a detected network problem with a suggested fix.
type Issue struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

// AlertType categorises what triggered an alert.
type AlertType string

const (
	AlertInternetDown  AlertType = "internet_down"
	AlertInternetUp    AlertType = "internet_up"
	AlertNewDevice     AlertType = "new_device"
	AlertIssueAppeared AlertType = "issue_appeared"
	AlertIssueCleared  AlertType = "issue_cleared"
	AlertDeviceOffline AlertType = "device_offline"
	AlertDeviceOnline  AlertType = "device_online"
)

// Alert records a notable network event.
type Alert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Type        AlertType `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	DeviceIP    string    `json:"device_ip,omitempty"`
	DeviceMAC   string    `json:"device_mac,omitempty"`
	IssueID     string    `json:"issue_id,omitempty"`
}

// PublicIPInfo holds data about the server's public IP.
type PublicIPInfo struct {
	IP      string `json:"query"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	ASN     string `json:"as"`
	City    string `json:"city"`
	Region  string `json:"regionName"`
	Country string `json:"country"`
}

// Snapshot is the full network state broadcast to clients.
type Snapshot struct {
	Timestamp        time.Time       `json:"timestamp"`
	Devices          []Device        `json:"devices"`
	DNS              []DNSResult     `json:"dns"`
	Internet         []InternetProbe `json:"internet"`
	Issues           []Issue         `json:"issues"`
	ServerIP         string          `json:"server_ip"`
	Gateway          string          `json:"gateway"`
	GatewayHostname  string          `json:"gateway_hostname"`
	GatewayRTT       int64           `json:"gateway_rtt_ms"`
	GatewayReachable bool            `json:"gateway_reachable"`
	GatewayPorts     []PortResult    `json:"gateway_ports"`
	Subnet           string          `json:"subnet"`
	DuplicateIPs     []string        `json:"duplicate_ips"`
	IPv6             bool            `json:"ipv6"`
	NTPSynced        *bool           `json:"ntp_synced"`
	PacketLossGW     float64         `json:"packet_loss_gw_pct"`
	PublicIP         *PublicIPInfo   `json:"public_ip,omitempty"`
	Traceroute       []TracerouteHop `json:"traceroute,omitempty"`
	AlertCount       int             `json:"alert_count"`
	WANDownloadMbps  float64         `json:"wan_download_mbps,omitempty"`
}

// IssueLogEntry records when an issue was first seen and when it cleared.
type IssueLogEntry struct {
	Issue
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	ClearedAt       *time.Time `json:"cleared_at,omitempty"`
	Active          bool       `json:"active"`
	OccurrenceCount int        `json:"occurrence_count"`
}

// HistoryPoint is a time-series data point for graphing.
type HistoryPoint struct {
	Time        time.Time `json:"t"`
	DeviceCount int       `json:"devices"`
	AvgLatency  int64     `json:"avg_latency_ms"`
	DNSOk       bool      `json:"dns_ok"`
	InternetOk  bool      `json:"internet_ok"`
}
