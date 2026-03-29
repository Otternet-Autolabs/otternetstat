# otternetstat — Development Conversation Log

This file captures the development history of otternetstat from initial concept through the LAN authorization feature, including user prompts, assistant responses, and design decisions made along the way.

---

## Background

otternetstat was the fourth application built in the session. The earlier work in the same conversation covered:
- **otn-profiler** — a macOS network-switching daemon (network-profiler-otn-sap.sh + LaunchAgent plist)
- **Heimdall Logs Toolbox** — a FastAPI web app for generating and verifying SAP DPI-anonymized log entries
- **ottermediator** — a Go Chromecast/media cockpit with WebSocket live status and DashCast integration

---

## Concept: Why otternetstat?

**User:** I have a teenager in the basement. He says the wifi is not working good, it works on some TVs but not on some of the phones. We don't know what it is so we need an application to run on the LAN to do statistics and analytics of the network.

**Assistant:** Planned otternetstat: Go + WebSocket backend, dark data-rich web UI, ARP scanning, DNS testing, internet reachability, per-device probing, issues panel with plain-English explanations.

**Outcome:** The application was built and subsequently diagnosed the actual issue.

**User (later):** The application suggested to change DNS and it solved everything [for the teenager].

---

## Initial Feature Set

### Core Architecture
- Go backend with `net/http` WebSocket hub
- ARP scan via `arping` / `arp -a`
- mDNS Bonjour service discovery
- Per-device probes: DNS, TCP port scan, ICMP ping latency
- Issues panel with human-readable explanations
- Dark data-rich frontend (vanilla JS + Canvas)

### Checks Added (both server-side and client-side)

**User:** Can you add more meaningful checks, both server side and client side?

**Decision:** Add all of the following:
- Gateway reachability + latency
- MTU / packet loss detection
- Per-device probes (DNS, port scan, ping)
- DHCP exhaustion detection
- NTP sync check
- Duplicate IP detection
- DoH comparison (Cloudflare vs Google)
- DNS hijack detection
- TLS certificate expiry
- WAN speed test (Cloudflare)
- Traceroute to 8.8.8.8
- mDNS / Bonjour service discovery
- Public IP / ISP info (ipapi.co, ip-api.com)
- MAC vendor lookup (macvendors.com)
- Bandwidth per device via gopacket/libpcap (CGO build, with no-op stub for cross-compile)

### Network Topology

**User:** Can you make it possible to expand network topology as a popover filling the screen?

Added fullscreen topology backdrop with ⤢ expand button. Shared `drawTopologyOnCanvas` function used for both inline canvas and fullscreen overlay. Nodes scale proportionally with available space.

---

## LAN Proof-of-Locality

### Concept

**User:** Would it be possible to introduce some way for a client to prove they are on the local network?

**Assistant:** Yes — dual-port HTTP listener approach:
- `:8007` — public server (nginx-proxied)
- `:8008` — LAN-only listener, bound exclusively to the LAN IP (RFC1918, not routed through nginx)

**Flow:**
1. Client requests a nonce from the public server (`GET /api/lan-challenge`)
2. Client fetches `http://<lan-ip>:8008/lan-verify/<nonce>` with `mode: 'no-cors'` — only reachable from inside the LAN
3. LAN listener marks the nonce as verified
4. Client polls `/api/lan-challenge/<nonce>/status` on the public server
5. When status is `"verified"`, the public server issues a signed session cookie

**User:** I like that idea — that was my idea too.

### Why the Cookie Must Come from `:8007`, Not `:8008`

Key design insight: setting the cookie on `:8008` (the LAN listener) would not work because the browser treats `localhost:8007` and `<lan-ip>:8008` as different origins under `SameSite=Strict`. A cookie set on `:8008` would never be sent to `:8007`.

**Fix:** The `challengeStatus` endpoint on the public server (`:8007`) issues the cookie when it detects the nonce has been verified. The LAN listener only marks the nonce — it never touches cookies.

### Session Cookie Format

Stateless HMAC-SHA256 signed token:
```
<16-byte-hex-random-token>.<SHA256-HMAC-of-token-keyed-with-server-secret>
```

- 32-byte server secret generated at startup via `crypto/rand` — not persisted, resets on server restart
- `HttpOnly: true`, `SameSite: Strict`, `Path: /`
- No `Max-Age` — browser session scoped
- Verification is stateless: recompute HMAC and compare with `hmac.Equal` (constant-time)

### Files Created / Modified

**`api/challenge.go`** (new):
- `ChallengeStore` — issues 16-byte hex nonces with 30s TTL, marks them verified, reports status ("pending" / "verified" / "expired")
- `newSessionToken(secret []byte)` — generates signed cookie value
- `validSessionCookie(value string, secret []byte) bool` — verifies HMAC

**`api/handlers.go`**:
- Added `secret []byte`, `challenges *ChallengeStore`, `lanPort int` to `Handler`
- `requireLAN(next http.HandlerFunc) http.HandlerFunc` — middleware checking `lan_session` cookie
- `issueChallenge` — returns nonce + LAN verify URL
- `challengeStatus` — issues cookie when nonce is verified; only sets new cookie if existing one is invalid
- `verifyChallenge` — LAN-only endpoint, marks nonce verified, returns 204
- `lanLogout` — clears cookie with `MaxAge: -1`
- `RegisterLANRoutes(mux)` — registers `/lan-verify/{nonce}` on the LAN-only mux

**Protected endpoints** (require valid `lan_session` cookie):
```
GET  /api/snapshot
GET  /api/history
GET  /api/issue-log
POST /api/scan
GET  /api/alerts
GET  /api/nicknames
PUT  /api/nicknames/{mac}
POST /api/wan-speed
GET  /ws
```

**Unprotected** (public):
```
GET  /                         (frontend HTML)
GET  /api/probe-asset          (speed test payload)
POST /api/probe-asset          (speed test upload sink)
GET  /api/lan-challenge        (issue nonce)
GET  /api/lan-challenge/{nonce}/status
GET  /api/share/{token}        (frozen snapshot)
GET  /lan-verify/{nonce}       (LAN-only :8008)
```

**`network/monitor.go`**:
- Added `ServerIP() string` — returns `m.serverIP` under RLock

**`main.go`**:
- `--lan-port` flag (default 8008)
- Generates 32-byte random secret at startup
- `detectLANIP(ifaceName string) string` — finds first non-loopback IPv4 on interface at startup (avoids timing issues with monitor's first scan)
- Starts second `http.Server` bound to `<lan-ip>:8008`
- Graceful shutdown of both servers

---

## Authorization: Outside-LAN UI

**User:** I want to use this as an authorization feature. When served on the internet, no server-side stuff should be exposed, only client-side stuff, and only client-side stuff that makes sense for a device outside of the LAN.

**Discussion:** Some server-side things are useful outside LAN:
- Public IP / ISP info (already server-fetched on startup)
- Frozen share snapshots (already scoped by token)

Everything else (live device data, issues, WAN speed, alerts, traceroute) requires LAN access.

### LAN Badge

`<span id="lan-badge" onclick="toggleLAN()">? LAN</span>`

States:
- `?` grey — not yet verified
- `✓` green — LAN session active
- `✗` red — outside LAN or session cleared

**User:** When I click the LAN badge it goes grey and immediately back to green. I suspect it accepts a new challenge.

**Fix:** Added `lan_suppressed` flag in `sessionStorage`. When user clicks ✓ to log out (`clearLAN()`), it sets `lan_suppressed = '1'`. `proveLAN()` checks this flag and skips auto-verification. The flag is cleared only on manual badge click (not on page reload), so logging out stays logged out for the session.

### Hidden Elements Outside LAN

**User:** If you look at the UI when a user is non-LAN, anything you think should be hidden for non-LAN users?

**Decision:** Hide everything that would be empty or LAN-internal:
- Network Topology
- Devices table
- LAN Latency History
- Gateway / Router panel
- Alerts panel
- Issues & Diagnostics panel
- Scan Now / Alerts / Share buttons
- WebSocket reconnecting status indicator

**Keep visible:**
- "This Device's Connectivity" — useful to any visitor (their own DNS, speed, connectivity)
- "Public IP / ISP" — shows server identity

**User:** The placement of the device box is a bit weird when it is alone.

**Fix:** `diagnostics-row` is a two-column CSS grid. When `gateway-panel-wrap` is hidden, set `gridTemplateColumns = '1fr'` so the connectivity panel stretches to full width.

### WebSocket Reconnect on 401

**User:** So when outside the LAN, there is a text "reconnecting..." in red.

**Fix:** In the WebSocket `onclose` handler, probe `/api/snapshot`. If the response is 401, stop reconnecting and hide the `ws-status` element entirely. Only reconnect on non-401 closures.

---

## Speed Test Labels

**User:** It says "LAN download speed" in the device connectivity box. Is it LAN or client?

**Clarification:** The probe asset download/upload tests go client→server, so it measures the path between the client and the otternetstat server — not a general internet speed test.

**User:** Make the wording clear that it is not general internet upload/download, but to the application/server.

**Decision:** Renamed to:
- "Download from server" (client downloads 512KB probe asset from otternetstat)
- "Upload to server" (client uploads to otternetstat's sink endpoint)

**User:** Can you add upload/download speed to internet from client?

Added two Cloudflare-based rows:
- "Internet download (via Cloudflare)" — client downloads from `speed.cloudflare.com/__down`
- "Internet upload (via Cloudflare)" — client uploads to `speed.cloudflare.com/__up`

Both go directly from browser to Cloudflare, with a label indicating this.

---

## DNS Display

**User:** Can you show which DNS the client is using?

**Answer:** Browsers don't expose the DNS server IP directly via any API.

**Approach implemented:** DNS consistency check:
- In Chrome/Edge: use `performance.getEntriesByName(url)[0].serverIPAddress` to get the actual IP used for a known domain
- Compare against DoH results from Cloudflare and Google
- If they agree → show "DNS consistent"
- If they differ → warn "DNS interception possible"
- Fallback for Firefox/Safari: check if Cloudflare DoH and Google DoH agree on lookup results

---

## Header Subtitle

**User:** Under the otternetstat logo, can you add "devices and packets" in a smaller font?

Added as a static string below the `<h1>`:
```html
<div id="header-sub">devices and packets</div>
```

CSS:
```css
#header-sub {
  font-size: 0.6rem;
  color: var(--muted);
  white-space: nowrap;
  margin-top: -2px;
  text-align: center;
}
```

---

## Key Design Decisions Summary

| Decision | Choice | Reason |
|---|---|---|
| LAN proof mechanism | Dual-port HTTP (`:8007` public + `:8008` LAN-only) | Cryptographic locality proof without VPN/certificates |
| Cookie origin | Issued by `:8007` (public), not `:8008` (LAN) | Browser SameSite rules prevent cross-origin cookie sharing |
| Session validation | Stateless HMAC-SHA256 | No session store needed; verification is a single HMAC recompute |
| Server secret | Ephemeral (not persisted) | Sessions expire on server restart; auto-reverify on next page load |
| `lan_suppressed` flag | `sessionStorage` | Resets on tab close; prevents auto-re-verify after deliberate logout |
| Outside-LAN panels | Hide all LAN-dependent UI | Empty boxes are confusing and expose that data exists |
| WebSocket on 401 | Stop reconnecting, hide status | Endless "reconnecting..." in red is confusing for outside-LAN visitors |
| Bandwidth capture | CGO with no-op stub | Keeps cross-compile working; libpcap optional at runtime |
| Traceroute | Hidden outside LAN | Shows hops from server to 8.8.8.8 — not useful to outside visitor |

---

## Bugs Fixed During Development

| Bug | Root Cause | Fix |
|---|---|---|
| Duplicate declarations in `challenge.go` | Edit tool prepended content instead of replacing | Read file, identified duplicate block, removed it |
| `inet-down`/`inet-up` rows not appearing | `renderClientRows()` `order` array missing them | Added both to render order |
| Badge immediately snapping back to green after logout | `clearLAN()` cleared `lan_reloaded` but `proveLAN()` ran again on reload | Added `lan_suppressed` sessionStorage flag |
| Connectivity panel half-width when alone | `diagnostics-row` is a 2-col grid; hidden sibling leaves gap | Set `gridTemplateColumns = '1fr'` dynamically |
| WebSocket "reconnecting..." on 401 | `onclose` handler always retried | Probe `/api/snapshot` on close; stop on 401 |
| `go build` exit 137 | Sudo session expired; `kill` command failed before new binary started | Re-run after sudo re-auth |
