package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// arpScan discovers devices on the local network via ARP ping.
func arpScan(ctx context.Context, iface *net.Interface) []*Device {
	cidr := localCIDR(iface)
	if cidr == "" {
		log.Printf("arpScan: could not determine local CIDR")
		return nil
	}
	log.Printf("arpScan: scanning %s", cidr)

	hosts := hostsInCIDR(cidr)
	results := make([]*Device, 0, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 64) // 64 concurrent pings

	for _, ip := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			rtt, ok := pingHost(ctx, ip)
			if !ok {
				return
			}
			dev := &Device{
				IP:  ip,
				RTT: rtt,
			}
			// Try to get hostname
			if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
				dev.Hostname = strings.TrimSuffix(names[0], ".")
			}
			// Try to get MAC from ARP cache
			dev.MAC = macFromARP(ip)
			dev.Vendor = vendorFromMAC(dev.MAC)
			dev.Status = StatusOnline
			mu.Lock()
			results = append(results, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
}

func pingHost(ctx context.Context, ip string) (int64, bool) {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1000", "-t", "1", ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	start := time.Now()
	if err := cmd.Run(); err != nil {
		return -1, false
	}
	return time.Since(start).Milliseconds(), true
}

func macFromARP(ip string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("arp", "-n", ip)
	} else {
		cmd = exec.Command("arp", "-n", ip)
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			fields := strings.Fields(line)
			for _, f := range fields {
				if isMACAddress(f) {
					return strings.ToUpper(f)
				}
			}
		}
	}
	return ""
}

func isMACAddress(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) == 6 {
		return true
	}
	parts = strings.Split(s, "-")
	return len(parts) == 6
}

func localCIDR(iface *net.Interface) string {
	var ifaces []net.Interface
	if iface != nil {
		ifaces = []net.Interface{*iface}
	} else {
		var err error
		ifaces, err = net.Interfaces()
		if err != nil {
			return ""
		}
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ipnet.String()
				}
			}
		}
	}
	return ""
}

func hostsInCIDR(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	size := 1 << (bits - ones)
	if size > 1024 {
		size = 1024 // cap at /22
	}
	hosts := make([]string, 0, size)
	ip := ipnet.IP.To4()
	for i := 1; i < size-1; i++ {
		next := make(net.IP, 4)
		copy(next, ip)
		next[3] = ip[3] + byte(i&0xff)
		next[2] = ip[2] + byte((i>>8)&0xff)
		hosts = append(hosts, next.String())
	}
	return hosts
}

func (m *Monitor) detectNetwork() {
	cidr := localCIDR(m.iface)
	if cidr == "" {
		return
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.serverIP = ip.String()
	m.subnet = ipnet.String()
	// Guess gateway as .1
	gw := make(net.IP, 4)
	copy(gw, ipnet.IP.To4())
	gw[3] = 1
	m.gateway = gw.String()
	m.mu.Unlock()
	log.Printf("Network: server=%s subnet=%s gateway=%s", ip, ipnet, gw)
}

// vendorFromMAC returns a rough vendor name from the MAC OUI prefix.
func vendorFromMAC(mac string) string {
	if mac == "" {
		return ""
	}
	// Normalize: take first 3 octets
	parts := strings.FieldsFunc(mac, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) < 3 {
		return ""
	}
	oui := strings.ToUpper(fmt.Sprintf("%s:%s:%s", parts[0], parts[1], parts[2]))
	if v, ok := ouiTable[oui]; ok {
		return v
	}
	return ""
}

// ouiTable is a small subset of common OUI prefixes.
var ouiTable = map[string]string{
	"00:50:56": "VMware",
	"00:0C:29": "VMware",
	"00:1A:11": "Google",
	"94:EB:CD": "Apple",
	"A4:C3:F0": "Apple",
	"3C:22:FB": "Apple",
	"DC:A6:32": "Raspberry Pi",
	"B8:27:EB": "Raspberry Pi",
	"E4:5F:01": "Raspberry Pi",
	"00:17:88": "Philips Hue",
	"EC:FA:BC": "Amazon",
	"FC:A6:67": "Amazon",
	"40:B4:CD": "Amazon",
	"7C:D5:66": "Samsung",
	"8C:77:12": "Samsung",
	"CC:32:E5": "Google",
	"20:DF:B9": "Google",
	"54:60:09": "Google",
	"6C:AD:F8": "Google",
	"F4:F5:D8": "Google",
	"AC:67:5D": "Google",
	"00:1B:63": "Apple",
	"00:26:BB": "Apple",
	"04:4B:ED": "Apple",
	"04:F7:E4": "Apple",
	"08:6D:41": "Apple",
	"10:40:F3": "Apple",
	"18:AF:61": "Apple",
	"1C:36:BB": "Apple",
	"28:CF:E9": "Apple",
	"34:36:3B": "Apple",
	"38:C9:86": "Apple",
	"40:CB:C0": "Apple",
	"44:D8:84": "Apple",
	"48:43:7C": "Apple",
	"4C:57:CA": "Apple",
	"58:B0:35": "Apple",
	"60:F8:1D": "Apple",
	"64:A3:CB": "Apple",
	"68:AB:1E": "Apple",
	"70:EC:E4": "Apple",
	"74:E1:B6": "Apple",
	"78:7B:8A": "Apple",
	"7C:C3:A1": "Apple",
	"88:66:A5": "Apple",
	"90:3C:92": "Apple",
	"98:00:C6": "Apple",
	"9C:F3:87": "Apple",
	"A8:86:DD": "Apple",
	"AC:BC:32": "Apple",
	"B8:09:8A": "Apple",
	"BC:3B:AF": "Apple",
	"C8:2A:14": "Apple",
	"CC:44:63": "Apple",
	"D0:23:DB": "Apple",
	"D8:1D:72": "Apple",
	"E0:B9:BA": "Apple",
	"E4:CE:8F": "Apple",
	"F0:D1:A9": "Apple",
	"F4:0F:24": "Apple",
	"00:26:5A": "Cisco",
	"00:17:94": "Cisco",
	"00:1E:E5": "Cisco",
	"E8:9F:80": "TP-Link",
	"C4:E9:84": "TP-Link",
	"50:C7:BF": "TP-Link",
	"14:CC:20": "TP-Link",
	"00:50:43": "Netgear",
	"20:E5:2A": "Netgear",
	"A0:04:60": "Netgear",
	"30:46:9A": "Netgear",
}
