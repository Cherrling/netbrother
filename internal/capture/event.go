package capture

import (
	"time"

	"github.com/netbrother/netbrother/internal/types"
)

// EventType indicates what kind of network event occurred.
type EventType int

const (
	EventNewConnection EventType = iota
	EventConnectionClosed
)

func (e EventType) String() string {
	switch e {
	case EventNewConnection:
		return "NEW_CONN"
	case EventConnectionClosed:
		return "CLOSE"
	default:
		return "UNKNOWN"
	}
}

// AlertType categorizes the kind of suspicious activity detected.
type AlertType int

const (
	AlertPeriodicConnection AlertType = iota
	AlertNewProcess
	AlertNewConnection
	AlertSuspiciousPort
	AlertSuspiciousIP
)

func (a AlertType) String() string {
	switch a {
	case AlertPeriodicConnection:
		return "PERIODIC"
	case AlertNewProcess:
		return "NEW_PROC"
	case AlertNewConnection:
		return "NEW_CONN"
	case AlertSuspiciousPort:
		return "SUSP_PORT"
	case AlertSuspiciousIP:
		return "SUSP_IP"
	default:
		return "UNKNOWN"
	}
}

// AlertSeverity indicates how serious an alert is.
type AlertSeverity int

const (
	SeverityInfo AlertSeverity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s AlertSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MED"
	case SeverityHigh:
		return "HIGH"
	default:
		return "??"
	}
}

// Alert represents a single suspicious activity alert.
type Alert struct {
	Type       AlertType
	Severity   AlertSeverity
	Message    string
	Connection types.Connection
	Timestamp  time.Time
}

// Event represents a network event from the capture layer.
type Event struct {
	Timestamp  time.Time
	Type       EventType
	Connection types.Connection
	Alerts     []Alert
}
