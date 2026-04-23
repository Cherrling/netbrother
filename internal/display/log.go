package display

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/netbrother/netbrother/internal/capture"
)

type logDisplayer struct {
	encoder *json.Encoder
	writer  io.Writer
	color   bool
	json    bool
	mu      sync.Mutex
}

func newLogDisplayer(cfg LogConfig) *logDisplayer {
	w := os.Stdout
	return &logDisplayer{
		encoder: json.NewEncoder(w),
		writer:  w,
		color:   cfg.Color,
		json:    cfg.JSON,
	}
}

func (l *logDisplayer) Close() error {
	return nil
}

func (l *logDisplayer) Start(ctx context.Context, events <-chan capture.Event) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			l.renderEvent(evt)
		}
	}
}

type logEvent struct {
	Timestamp  string        `json:"timestamp"`
	EventType  string        `json:"event_type"`
	Connection logConnection `json:"connection"`
	Alerts     []logAlert    `json:"alerts,omitempty"`
}

type logConnection struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	PID        int    `json:"pid"`
	Process    string `json:"process"`
	Direction  string `json:"direction"`
	State      string `json:"state"`
}

type logAlert struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func (l *logDisplayer) renderEvent(evt capture.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.json {
		l.renderJSON(evt)
	} else {
		l.renderText(evt)
	}
}

func (l *logDisplayer) renderJSON(evt capture.Event) {
	le := logEvent{
		Timestamp: evt.Timestamp.Format(time.RFC3339Nano),
		EventType: evt.Type.String(),
		Connection: logConnection{
			LocalIP:    evt.Connection.LocalIP.String(),
			LocalPort:  evt.Connection.LocalPort,
			RemoteIP:   evt.Connection.RemoteIP.String(),
			RemotePort: evt.Connection.RemotePort,
			PID:        evt.Connection.PID,
			Process:    evt.Connection.ProcessName,
			Direction:  evt.Connection.Direction.String(),
			State:      evt.Connection.State.String(),
		},
	}

	for _, a := range evt.Alerts {
		le.Alerts = append(le.Alerts, logAlert{
			Type:     a.Type.String(),
			Severity: a.Severity.String(),
			Message:  a.Message,
		})
	}

	l.encoder.Encode(le)
}

func (l *logDisplayer) renderText(evt capture.Event) {
	ts := evt.Timestamp.Format("15:04:05.000")
	conn := evt.Connection

	pidStr := fmt.Sprintf("%d", conn.PID)
	if conn.PID == 0 {
		pidStr = "?"
	}

	eventType := evt.Type.String()
	localAddr := fmt.Sprintf("%s:%d", conn.LocalIP, conn.LocalPort)
	remoteAddr := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)

	fmt.Fprintf(l.writer, "%s %-9s %5s %-20s %-21s %s %-8s",
		ts, eventType, conn.ProcessName, localAddr, remoteAddr, conn.State.String(), pidStr)

	if len(evt.Alerts) > 0 {
		for _, a := range evt.Alerts {
			fmt.Fprintf(l.writer, "  [%s] %s", a.Severity.String(), a.Message)
		}
	}

	fmt.Fprintln(l.writer)
}
