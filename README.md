# otternetstat

**devices and packets**

A self-hosted LAN network monitor that runs on your local network and gives you a live, browser-based dashboard of every device, DNS health, internet connectivity, and detected issues — with plain-English explanations of what's wrong and what to do about it.

Built in Go. Single binary. No dependencies to install at runtime (libpcap optional for per-device bandwidth).

---

## What it does

- **Discovers all devices** on your LAN via ARP scan, with MAC vendor lookup and mDNS/Bonjour service detection
- **Monitors internet connectivity** with ICMP probes, packet loss measurement, and latency history graphs
- **Checks DNS health** — tests multiple resolvers, detects hijacking, compares Cloudflare DoH vs Google DoH
- **Detects network issues** and explains them in plain English with suggested fixes (duplicate IPs, DNS failures, high latency, offline devices, etc.)
- **Tracks TLS certificate expiry** for devices with HTTPS
- **Runs a traceroute** to 8.8.8.8 to show your path to the internet
- **Measures WAN speed** via Cloudflare
- **Captures per-device bandwidth** (requires CGO + libpcap)
- **Alerts** on internet up/down, new devices, and issue state changes
- **Persists device nicknames** across restarts
- **Share links** — generate a frozen snapshot URL to share with others
- **LAN proof-of-locality** — the dashboard proves whether you're on the LAN and gates all sensitive data behind a session cookie

---

## Screenshots

The dashboard runs in the browser at `http://localhost:8007` (or wherever you deploy it).

- Dark UI with live WebSocket updates
- Network topology canvas with fullscreen expand
- Per-device popover with all probe results
- Latency history graph
- Issues & Diagnostics panel
- "This Device's Connectivity" panel (works outside LAN too)

---

## Quick start

### Prerequisites

- Go 1.22+
- macOS or Linux
- Root/sudo access (required for ARP scanning and ICMP probes)

### Build and run

```bash
git clone https://github.com/Otternet-Autolabs/otternetstat
cd otternetstat
go build -o otternetstat .
sudo ./otternetstat --iface en0
```

Open `http://localhost:8007` in your browser.

> **Note:** `sudo` is required because ARP scanning and raw ICMP need elevated privileges on most systems.

### With libpcap (per-device bandwidth)

```bash
# macOS
brew install libpcap

# Debian/Ubuntu
sudo apt install libpcap-dev

# Build with CGO enabled (default)
CGO_ENABLED=1 go build -o otternetstat .
sudo ./otternetstat --iface en0
```

Without libpcap the binary builds and runs fine — bandwidth columns just show `—`.

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--iface` | auto-detect | Network interface to scan (e.g. `en0`, `eth0`) |
| `--port` | `8007` | HTTP port for the public server |
| `--lan-port` | `8008` | LAN-only HTTP port for locality proof |

The `PORT` environment variable overrides `--port` if set (useful for container deployments).

### Interface selection

If `--iface` is omitted, otternetstat scans all non-loopback interfaces. On multi-homed hosts (e.g. both WiFi and Ethernet active) you should specify `--iface` to ensure scanning targets the correct subnet.

```bash
# macOS WiFi
sudo ./otternetstat --iface en0

# macOS Ethernet
sudo ./otternetstat --iface en1

# Linux
sudo ./otternetstat --iface eth0
```

---

## LAN authorization

otternetstat supports being served publicly (e.g. behind nginx) while keeping all sensitive network data private to LAN visitors.

### How it works

Two HTTP listeners run simultaneously:
- **`:8007`** (public) — serves the frontend, challenge endpoints, and share links
- **`:8008`** (LAN-only) — bound exclusively to the LAN IP; unreachable from the internet

When you open the dashboard, the browser automatically runs a **proof-of-locality** check:
1. Requests a nonce from the public server
2. Fetches `http://<lan-ip>:8008/lan-verify/<nonce>` — only reachable from inside the LAN
3. Polls the public server for verification status
4. On success, the public server issues a signed session cookie (`lan_session`)

All sensitive API endpoints require a valid `lan_session` cookie. Without it they return `401 {"error":"lan_required"}`.

### What's visible outside the LAN

- The dashboard frontend
- "This Device's Connectivity" panel (your own DNS/speed diagnostics)
- Public IP / ISP info
- Share snapshot links

Everything else (live device list, issues, gateway data, alerts, topology) requires LAN proof.

### LAN badge

The header shows a **LAN badge**:
- `? LAN` — checking
- `✓ LAN` — verified, click to log out
- `✗ LAN` — outside LAN or session cleared, click to re-verify

---

## Nginx proxy example

```nginx
server {
    listen 443 ssl;
    server_name netstat.example.com;

    # Forward all traffic to otternetstat
    location / {
        proxy_pass http://127.0.0.1:8007;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

The LAN listener (`:8008`) is bound to the private LAN IP and never exposed through nginx — this is the security property that makes the locality proof work.

---

## Data persistence

Device nicknames are saved to `otternetstat.json` in the same directory as the binary. The file is created automatically on first use.

Session secrets are **not** persisted — they are regenerated at startup. Existing browser sessions will need to re-verify after a server restart (this happens automatically in the background).

---

## API

All endpoints except those listed as "public" require a valid `lan_session` cookie.

### Public endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Frontend HTML (single-page app) |
| `GET` | `/api/probe-asset` | 512KB payload for client bandwidth measurement |
| `POST` | `/api/probe-asset` | Upload sink for client upload measurement |
| `GET` | `/api/lan-challenge` | Issue a locality nonce |
| `GET` | `/api/lan-challenge/{nonce}/status` | Poll nonce verification status |
| `GET` | `/api/share/{token}` | Fetch a frozen snapshot share |
| `GET` | `/api/lan-logout` | Clear the session cookie |

### Protected endpoints (LAN session required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/snapshot` | Current network state |
| `GET` | `/api/history` | Latency/status time series |
| `GET` | `/api/issue-log` | Full issue history with timestamps |
| `POST` | `/api/scan` | Trigger an immediate ARP scan |
| `GET` | `/api/alerts` | Last 200 alerts |
| `GET` | `/api/nicknames` | All device nicknames |
| `PUT` | `/api/nicknames/{mac}` | Set a device nickname |
| `POST` | `/api/wan-speed` | Trigger WAN speed measurement |
| `GET` | `/ws` | WebSocket (live push updates) |

### LAN-only endpoint

| Method | Path | Server | Description |
|---|---|---|---|
| `GET` | `/lan-verify/{nonce}` | `:8008` | Mark nonce as verified (locality proof) |

---

## Architecture

```
otternetstat/
├── main.go                  # Entry point, server setup, LAN IP detection
├── frontend/
│   └── index.html           # Single-file SPA (embedded into binary)
├── api/
│   ├── handlers.go          # HTTP handlers and requireLAN middleware
│   ├── challenge.go         # LAN proof nonce store + HMAC session tokens
│   ├── share.go             # Frozen snapshot share store (TTL 1h)
│   └── websocket.go         # WebSocket hub
└── network/
    ├── types.go             # All data types (Device, Snapshot, Issue, Alert, …)
    ├── monitor.go           # Central state machine, scan loop, issue evaluation
    ├── scan.go              # ARP scan, mDNS, hostname resolution, port probes
    ├── issues.go            # Issue detection logic
    ├── probes.go            # WAN speed, public IP, NTP sync
    ├── traceroute.go        # Traceroute runner and parser
    ├── certs.go             # TLS certificate expiry checker
    ├── store.go             # JSON persistence for nicknames
    ├── bandwidth.go         # Per-device bandwidth via gopacket/libpcap (CGO)
    └── bandwidth_stub.go    # No-op stubs when CGO is disabled
```

The frontend is a single HTML file embedded into the binary at build time using Go's `embed` package. No separate static file server or build step is needed.

---

## Building without CGO

For cross-compilation or environments without libpcap:

```bash
CGO_ENABLED=0 go build -o otternetstat .
```

Per-device bandwidth (`rx_bps`, `tx_bps`) will always be zero, everything else works normally.

### Cross-compile for Linux from macOS

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o otternetstat-linux-amd64 .
```

---

## Running as a system service (macOS)

Create `/Library/LaunchDaemons/com.otternet.otternetstat.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.otternet.otternetstat</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/otternetstat</string>
        <string>--iface</string>
        <string>en0</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/otternetstat.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/otternetstat.log</string>
</dict>
</plist>
```

```bash
sudo cp otternetstat /usr/local/bin/
sudo launchctl load /Library/LaunchDaemons/com.otternet.otternetstat.plist
```

### Running as a systemd service (Linux)

```ini
[Unit]
Description=otternetstat LAN monitor
After=network.target

[Service]
ExecStart=/usr/local/bin/otternetstat --iface eth0
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp otternetstat /usr/local/bin/
sudo systemctl enable --now otternetstat
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/gorilla/websocket` | WebSocket server |
| `github.com/miekg/dns` | DNS over HTTPS (DoH) queries |
| `github.com/google/gopacket` | Per-device bandwidth capture (CGO only) |
| Standard library | Everything else |

---

## License

MIT
