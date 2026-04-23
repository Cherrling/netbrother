package detect

import (
	"fmt"
	"sync"

	"github.com/netbrother/netbrother/internal/capture"
	"github.com/netbrother/netbrother/internal/types"
)

type noveltyDetector struct {
	mu              sync.Mutex
	seenProcesses   map[int]bool
	seenConnections map[types.ConnectionKey]bool
}

func newNoveltyDetector() *noveltyDetector {
	return &noveltyDetector{
		seenProcesses:   make(map[int]bool),
		seenConnections: make(map[types.ConnectionKey]bool),
	}
}

func (d *noveltyDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seenProcesses = make(map[int]bool)
	d.seenConnections = make(map[types.ConnectionKey]bool)
}

func (d *noveltyDetector) Analyze(evt capture.Event) []capture.Alert {
	if evt.Type != capture.EventNewConnection {
		return nil
	}

	conn := evt.Connection
	now := evt.Timestamp

	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []capture.Alert

	// New process detection
	if conn.PID > 0 && !d.seenProcesses[conn.PID] {
		d.seenProcesses[conn.PID] = true
		procName := conn.ProcessName
		if procName == "" {
			procName = "?"
		}
		alerts = append(alerts, capture.Alert{
			Type:       capture.AlertNewProcess,
			Severity:   capture.SeverityMedium,
			Message:    fmt.Sprintf("New process: PID %d (%s) making connections", conn.PID, procName),
			Connection: conn,
			Timestamp:  now,
		})
	}

	// New connection detection
	key := conn.Key()
	if !d.seenConnections[key] {
		d.seenConnections[key] = true
		alerts = append(alerts, capture.Alert{
			Type:     capture.AlertNewConnection,
			Severity: capture.SeverityInfo,
			Message: fmt.Sprintf("New connection: %s:%d -> %s:%d",
				conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort),
			Connection: conn,
			Timestamp:  now,
		})
	}

	return alerts
}
