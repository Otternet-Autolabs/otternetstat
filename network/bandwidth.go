//go:build cgo

package network

import (
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type bwBucket struct {
	rx uint64
	tx uint64
}

var (
	bwMu      sync.Mutex
	bwCurrent = map[string]*bwBucket{} // accumulate during window
	bwResult  = map[string][2]float64{} // ip → [rxBps, txBps]
)

func StartBandwidthCapture(ifaceName, serverIP string) {
	if ifaceName == "" {
		return
	}
	handle, err := pcap.OpenLive(ifaceName, 96, true, pcap.BlockForever)
	if err != nil {
		log.Printf("bandwidth capture: %v (skipping)", err)
		return
	}
	if err := handle.SetBPFFilter("ip"); err != nil {
		log.Printf("bandwidth BPF filter: %v", err)
		handle.Close()
		return
	}
	log.Printf("bandwidth capture started on %s", ifaceName)
	go captureLoop(handle, serverIP)
	go bwRollup()
}

func captureLoop(handle *pcap.Handle, serverIP string) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		ipLayer := pkt.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip := ipLayer.(*layers.IPv4)
		length := uint64(len(pkt.Data()))
		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()

		bwMu.Lock()
		if srcIP == serverIP {
			// outbound: counts as TX for the destination device
			b := bwBucketFor(dstIP)
			b.tx += length
		} else if dstIP == serverIP {
			// inbound: counts as RX for the source device
			b := bwBucketFor(srcIP)
			b.rx += length
		}
		bwMu.Unlock()
	}
}

func bwBucketFor(ip string) *bwBucket {
	b, ok := bwCurrent[ip]
	if !ok {
		b = &bwBucket{}
		bwCurrent[ip] = b
	}
	return b
}

func bwRollup() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		bwMu.Lock()
		next := map[string]*bwBucket{}
		for ip, b := range bwCurrent {
			bwResult[ip] = [2]float64{float64(b.rx) / 5.0, float64(b.tx) / 5.0}
			next[ip] = &bwBucket{}
		}
		bwCurrent = next
		bwMu.Unlock()
	}
}

func GetBandwidth(ip string) (rxBps, txBps float64) {
	bwMu.Lock()
	defer bwMu.Unlock()
	if v, ok := bwResult[ip]; ok {
		return v[0], v[1]
	}
	return 0, 0
}
