package api

import (
	"encoding/json"
	"net/http"

	"github.com/i574789/otternetstat/network"
)

type Handler struct {
	monitor *network.Monitor
}

func NewHandler(monitor *network.Monitor) *Handler {
	return &Handler{monitor: monitor}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, hub *Hub) {
	mux.HandleFunc("GET /api/snapshot", h.snapshot)
	mux.HandleFunc("GET /api/history", h.history)
	mux.HandleFunc("POST /api/scan", h.triggerScan)
	mux.HandleFunc("GET /ws", hub.ServeWS)

	// Set hub snapshot function
	hub.SetSnapshot(func() []byte {
		snap := h.monitor.Snapshot()
		b, _ := json.Marshal(map[string]interface{}{
			"type": "snapshot",
			"data": snap,
		})
		return b
	})
}

func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.Snapshot())
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.monitor.History())
}

func (h *Handler) triggerScan(w http.ResponseWriter, r *http.Request) {
	go h.monitor.TriggerScan()
	writeJSON(w, map[string]string{"status": "scanning"})
}
