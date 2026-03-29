//go:build !cgo

package network

func StartBandwidthCapture(ifaceName, serverIP string) {}
func GetBandwidth(ip string) (float64, float64)        { return 0, 0 }
