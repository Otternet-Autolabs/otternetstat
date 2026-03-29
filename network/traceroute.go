package network

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var (
	// " 1  router.local (192.168.1.1)  1.234 ms"
	// " 1  192.168.1.1  1.234 ms"
	hopLine = regexp.MustCompile(`^\s*(\d+)\s+(?:(\S+)\s+\((\S+)\)\s+|(\S+)\s+)(\d+(?:\.\d+)?)\s+ms`)
	// " 2  * * *"
	timeoutLine = regexp.MustCompile(`^\s*(\d+)\s+\*`)
)

// RunTraceroute runs traceroute to 8.8.8.8 and returns parsed hops.
func RunTraceroute(ctx context.Context) []TracerouteHop {
	target := "8.8.8.8"
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "traceroute", "-m", "20", "-q", "1", "-w", "2", target)
	} else {
		cmd = exec.CommandContext(ctx, "traceroute", "-m", "20", "-q", "1", "-w", "2", "-n", target)
	}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseTraceroute(string(out))
}

func parseTraceroute(output string) []TracerouteHop {
	var hops []TracerouteHop
	for _, line := range strings.Split(output, "\n") {
		if m := hopLine.FindStringSubmatch(line); m != nil {
			hop, _ := strconv.Atoi(m[1])
			hostname := m[2]
			ip := m[3]
			if ip == "" {
				ip = m[4]
			}
			if hostname == "" {
				hostname = ip
			}
			rttF, _ := strconv.ParseFloat(m[5], 64)
			hops = append(hops, TracerouteHop{
				Hop:      hop,
				IP:       ip,
				Hostname: strings.TrimSuffix(hostname, "."),
				RTTMs:    int64(rttF),
			})
		} else if m := timeoutLine.FindStringSubmatch(line); m != nil {
			hop, _ := strconv.Atoi(m[1])
			hops = append(hops, TracerouteHop{Hop: hop, Timeout: true})
		}
	}
	return hops
}
