package main

import (
	"context"
	"crypto/rand"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
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
	lanPort := flag.Int("lan-port", 8008, "LAN-only HTTP port for locality proof")
	iface := flag.String("iface", "", "Network interface to scan (e.g. en0, eth0)")
	flag.Parse()

	if p := os.Getenv("PORT"); p != "" && *port == 8007 {
		fmt.Sscanf(p, "%d", port)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	hub := api.NewHub()
	go hub.Run()

	monitor := network.NewMonitor(*iface, hub, network.DefaultStorePath())
	go monitor.Start(ctx)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal("failed to generate session secret:", err)
	}

	mux := http.NewServeMux()

	// Frontend
	sub, _ := fs.Sub(frontendFS, "frontend")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	// API
	h := api.NewHandler(monitor, *lanPort, secret)
	h.RegisterRoutes(mux, hub)

	addr := fmt.Sprintf(":%d", *port)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Printf("otternetstat listening on http://localhost:%d", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// LAN-only listener: discover LAN IP and bind exclusively to it.
	// Unreachable from outside the LAN (RFC1918 address never routed through nginx).
	var lanSrv *http.Server
	if lanIP := detectLANIP(*iface); lanIP != "" {
		lanMux := http.NewServeMux()
		h.RegisterLANRoutes(lanMux)
		lanAddr := fmt.Sprintf("%s:%d", lanIP, *lanPort)
		lanSrv = &http.Server{Addr: lanAddr, Handler: lanMux}
		go func() {
			log.Printf("LAN-only listener on http://%s (locality proof)", lanAddr)
			if err := lanSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("LAN listener error (non-fatal): %v", err)
			}
		}()
	} else {
		log.Printf("LAN listener skipped: could not detect LAN IP (use --iface to specify interface)")
	}

	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	srv.Shutdown(shutCtx)
	if lanSrv != nil {
		lanSrv.Shutdown(shutCtx)
	}
}

// detectLANIP returns the first non-loopback, non-link-local IPv4 address
// on the named interface (or any interface if ifaceName is "").
func detectLANIP(ifaceName string) string {
	var ifaces []net.Interface
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return ""
		}
		ifaces = []net.Interface{*iface}
	} else {
		var err error
		ifaces, err = net.Interfaces()
		if err != nil {
			return ""
		}
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}
