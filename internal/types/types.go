package types

import (
	"net"
	"time"
)

// ConnectionState mirrors TCP states from /proc/net/tcp.
type ConnectionState int

const (
	StateEstablished ConnectionState = 1 + iota
	StateSynSent
	StateSynRecv
	StateFinWait1
	StateFinWait2
	StateTimeWait
	StateClose
	StateCloseWait
	StateLastAck
	StateListen
	StateClosing
)

var stateNames = [...]string{
	"",
	"ESTAB",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

func (s ConnectionState) String() string {
	if s >= 1 && int(s) < len(stateNames) {
		return stateNames[s]
	}
	return "UNKNOWN"
}

// ConnectionDirection indicates whether this is an outbound or inbound connection.
type ConnectionDirection int

const (
	DirectionUnknown ConnectionDirection = iota
	DirectionOutbound
	DirectionInbound
)

func (d ConnectionDirection) String() string {
	switch d {
	case DirectionOutbound:
		return "OUT"
	case DirectionInbound:
		return "IN"
	default:
		return "??"
	}
}

// Connection is the canonical representation of a single TCP connection.
type Connection struct {
	LocalIP     net.IP
	LocalPort   uint16
	RemoteIP    net.IP
	RemotePort  uint16
	PID         int
	ProcessName string
	Inode       uint64
	State       ConnectionState
	Direction   ConnectionDirection
	CreatedAt   time.Time
}

// ConnectionKey is a comparable map key for deduplication.
type ConnectionKey struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	PID        int
}

func (c Connection) Key() ConnectionKey {
	return ConnectionKey{
		LocalIP:    c.LocalIP.String(),
		LocalPort:  c.LocalPort,
		RemoteIP:   c.RemoteIP.String(),
		RemotePort: c.RemotePort,
		PID:        c.PID,
	}
}

// ProcessSnapshot is a lightweight representation for display.
type ProcessSnapshot struct {
	PID         int
	Name        string
	Connections int
}
