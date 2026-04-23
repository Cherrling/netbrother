package detect

import (
	"fmt"
	"net"
	"sync"

	"github.com/netbrother/netbrother/internal/capture"
)

type suspiciousDetector struct {
	mu       sync.Mutex
	badPorts []PortRange
	badIPs   []*net.IPNet
}

func newSuspiciousDetector(cfg Config) *suspiciousDetector {
	d := &suspiciousDetector{
		badPorts: cfg.BadPorts,
	}

	for _, s := range cfg.BadIPs {
		if s == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(s)
		if err == nil {
			d.badIPs = append(d.badIPs, cidr)
		}
	}

	return d
}

func (d *suspiciousDetector) Reset() {
	// No state to reset (static rules)
}

func (d *suspiciousDetector) Analyze(evt capture.Event) []capture.Alert {
	if evt.Type != capture.EventNewConnection {
		return nil
	}

	conn := evt.Connection
	now := evt.Timestamp

	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []capture.Alert

	// Check suspicious ports
	port := conn.RemotePort
	for _, pr := range d.badPorts {
		if port >= pr.Start && port <= pr.End {
			alerts = append(alerts, capture.Alert{
				Type:       capture.AlertSuspiciousPort,
				Severity:   capture.SeverityMedium,
				Message:    fmt.Sprintf("Suspicious port %d (range %d-%d)", port, pr.Start, pr.End),
				Connection: conn,
				Timestamp:  now,
			})
			break
		}
	}

	// Check suspicious IPs
	if conn.RemoteIP != nil {
		for _, cidr := range d.badIPs {
			if cidr.Contains(conn.RemoteIP) {
				alerts = append(alerts, capture.Alert{
					Type:       capture.AlertSuspiciousIP,
					Severity:   capture.SeverityHigh,
					Message:    fmt.Sprintf("Connection to suspicious IP %s (in %s)", conn.RemoteIP, cidr),
					Connection: conn,
					Timestamp:  now,
				})
				break
			}
		}
	}

	return alerts
}
