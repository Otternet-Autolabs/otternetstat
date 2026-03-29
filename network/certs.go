package network

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// CheckCert dials host:443 and returns TLS certificate expiry info.
// InsecureSkipVerify is intentional — we want to inspect even expired/self-signed certs.
func CheckCert(ctx context.Context, host string) *CertInfo {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 4 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return &CertInfo{Host: host, Error: err.Error()}
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return &CertInfo{Host: host, Error: "no certificates presented"}
	}
	cert := certs[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return &CertInfo{
		Host:     host,
		NotAfter: cert.NotAfter,
		DaysLeft: daysLeft,
	}
}
