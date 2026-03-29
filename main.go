package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/i574789/otternetstat/api"
	"github.com/i574789/otternetstat/network"
)

//go:embed frontend/index.html
var frontendFS embed.FS

func main() {
	port := flag.Int("port", 8007, "HTTP port")
	iface := flag.String("iface", "", "Network interface to scan (e.g. en0, eth0)")
	flag.Parse()

	if p := os.Getenv("PORT"); p != "" && *port == 8007 {
		fmt.Sscanf(p, "%d", port)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	hub := api.NewHub()
	go hub.Run()

	monitor := network.NewMonitor(*iface, hub)
	go monitor.Start(ctx)

	mux := http.NewServeMux()

	// Frontend
	sub, _ := fs.Sub(frontendFS, "frontend")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	// API
	h := api.NewHandler(monitor)
	h.RegisterRoutes(mux, hub)

	addr := fmt.Sprintf(":%d", *port)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Printf("otternetstat listening on http://localhost:%d", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	srv.Shutdown(shutCtx)
}
