package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/i574789/otternetstat/network"
)

type Handler struct {
	monitor    *network.Monitor
	shares     *ShareStore
	challenges *ChallengeStore
	lanPort    int
	secret     []byte
}

func NewHandler(monitor *network.Monitor, lanPort int, secret []byte) *Handler {
	return &Handler{
		monitor:    monitor,
		shares:     NewShareStore(),
		challenges: NewChallengeStore(),
		lanPort:    lanPort,
		secret:     secret,
	}
}

// probeAsset is a 512KB payload used for client-side bandwidth estimation.
var probeAsset = make([]byte, 512*1024)

func (h *Handler) RegisterRoutes(mux *http.ServeMux, hub *Hub) {
	mux.HandleFunc("GET /api/snapshot",        h.requireLAN(h.snapshot))
	mux.HandleFunc("GET /api/history",         h.requireLAN(h.history))
	mux.HandleFunc("GET /api/issue-log",       h.requireLAN(h.issueLog))
	mux.HandleFunc("POST /api/scan",           h.requireLAN(h.triggerScan))
	mux.HandleFunc("GET /api/probe-asset",     h.probeAssetHandler)
	mux.HandleFunc("POST /api/probe-asset",    h.probeUploadHandler)
	mux.HandleFunc("GET /api/alerts",          h.requireLAN(h.alerts))
	mux.HandleFunc("GET /api/nicknames",       h.requireLAN(h.getNicknames))
	mux.HandleFunc("PUT /api/nicknames/{mac}", h.requireLAN(h.putNickname))
	mux.HandleFunc("GET /api/share",           h.requireLAN(h.createShare))
	mux.HandleFunc("GET /api/share/{token}",   h.getShare)
	mux.HandleFunc("POST /api/wan-speed",      h.requireLAN(h.wanSpeed))
	mux.HandleFunc("GET /api/lan-challenge",   h.issueChallenge)
	mux.HandleFunc("GET /api/lan-challenge/{nonce}/status", h.challengeStatus)
	mux.HandleFunc("GET /api/lan-logout", h.lanLogout)
	mux.HandleFunc("GET /ws",                  h.requireLAN(hub.ServeWS))

	hub.SetSnapshot(func() []byte {
		snap := h.monitor.Snapshot()
		b, _ := json.Marshal(map[string]interface{}{
			"type": "snapshot",
			"data": snap,
		})
		return b
	})
}

// requireLAN wraps a handler to require a valid lan_session cookie.
// Returns 401 if the cookie is absent or has an invalid signature.
func (h *Handler) requireLAN(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("lan_session")
		if err != nil || !validSessionCookie(c.Value, h.secret) {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"lan_required"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.Snapshot())
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.History())
}

func (h *Handler) issueLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.IssueLog())
}

func (h *Handler) triggerScan(w http.ResponseWriter, r *http.Request) {
	go h.monitor.TriggerScan()
	writeJSON(w, map[string]string{"status": "scanning"})
}

func (h *Handler) probeAssetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "524288")
	w.Write(probeAsset)
}

func (h *Handler) probeUploadHandler(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, io.LimitReader(r.Body, 10*1024*1024))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) alerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.Alerts())
}

func (h *Handler) getNicknames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.Nicknames())
}

func (h *Handler) putNickname(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	var body struct {
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&body); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if err := h.monitor.SetNickname(mac, body.Nickname); err != nil {
		http.Error(w, "save failed", 500)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) createShare(w http.ResponseWriter, r *http.Request) {
	snap := h.monitor.Snapshot()
	token := h.shares.Create(snap)
	writeJSON(w, map[string]string{"token": token})
}

func (h *Handler) getShare(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	snap, ok := h.shares.Get(token)
	if !ok {
		http.Error(w, "not found or expired", 404)
		return
	}
	writeJSON(w, snap)
}

func (h *Handler) wanSpeed(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 35000000000) // 35s
	defer cancel()
	mbps := network.ProbeWANSpeed(ctx)
	h.monitor.SetWANSpeed(mbps)
	writeJSON(w, map[string]float64{"mbps": mbps})
}

// RegisterLANRoutes registers routes on the LAN-only mux (port 8008).
func (h *Handler) RegisterLANRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /lan-verify/{nonce}", h.verifyChallenge)
}

func (h *Handler) issueChallenge(w http.ResponseWriter, r *http.Request) {
	nonce := h.challenges.Issue()
	if nonce == "" {
		http.Error(w, "failed to generate nonce", 500)
		return
	}
	lanIP := h.monitor.ServerIP()
	writeJSON(w, map[string]string{
		"nonce":   nonce,
		"lan_url": fmt.Sprintf("http://%s:%d/lan-verify/%s", lanIP, h.lanPort, nonce),
	})
}

func (h *Handler) challengeStatus(w http.ResponseWriter, r *http.Request) {
	nonce := r.PathValue("nonce")
	status := h.challenges.Status(nonce)
	if status == "verified" {
		// Issue a signed session cookie scoped to this origin (:8007).
		// Only set it if the client doesn't already have a valid one.
		if c, err := r.Cookie("lan_session"); err != nil || !validSessionCookie(c.Value, h.secret) {
			if cookieVal, err := newSessionToken(h.secret); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     "lan_session",
					Value:    cookieVal,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
			}
		}
	}
	writeJSON(w, map[string]string{"status": status})
}

func (h *Handler) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	nonce := r.PathValue("nonce")
	h.challenges.Verify(nonce)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) lanLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "lan_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, map[string]string{"status": "logged_out"})
}
