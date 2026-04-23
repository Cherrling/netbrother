package capture

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/netbrother/netbrother/internal/process"
	"github.com/netbrother/netbrother/internal/types"
)

func init() {
	procDetect = func() bool {
		return true // /proc is always available on Linux
	}
}

type procCapturer struct {
	mu        sync.Mutex
	interval  time.Duration
	known     map[types.ConnectionKey]bool // tracks connections from previous poll
}

func newProcCapturer() (*procCapturer, error) {
	return &procCapturer{
		interval: 1 * time.Second,
		known:    make(map[types.ConnectionKey]bool),
	}, nil
}

func (p *procCapturer) Name() string {
	return "proc"
}

func (p *procCapturer) RequiresRoot() bool {
	return false
}

func (p *procCapturer) Close() error {
	return nil
}

func (p *procCapturer) Start(ctx context.Context) (<-chan Event, error) {
	events := make(chan Event)
	go p.poll(ctx, events)
	return events, nil
}

func (p *procCapturer) poll(ctx context.Context, events chan<- Event) {
	defer close(events)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Do an initial scan to populate known connections
	p.scanAndEmit(ctx, events)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.scanAndEmit(ctx, events)
		}
	}
}

func (p *procCapturer) scanAndEmit(ctx context.Context, events chan<- Event) {
	now := time.Now()

	rawConns, err := process.ListTCPConnections()
	if err != nil {
		return
	}

	// Build inode -> PID map once per scan (expensive)
	pidMap, err := process.AllPIDsWithFds()
	if err != nil {
		return
	}
	// Also build inode -> PID reverse map
	inodeToPID := make(map[uint64]int)
	for pid, inodes := range pidMap {
		for _, inode := range inodes {
			inodeToPID[inode] = pid
		}
	}

	currentKeys := make(map[types.ConnectionKey]bool)
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, raw := range rawConns {
		// Skip LISTEN sockets — we only care about established connections
		if raw.State == int(types.StateListen) {
			continue
		}

		conn := rawToConnection(raw, inodeToPID, now)
		key := conn.Key()
		currentKeys[key] = true

		if !p.known[key] {
			p.known[key] = true
			select {
			case events <- Event{
				Timestamp:  now,
				Type:       EventNewConnection,
				Connection: conn,
			}:
			case <-ctx.Done():
				return
			}
		}
	}

	// Detect closed connections
	for key := range p.known {
		if !currentKeys[key] {
			delete(p.known, key)
			// Reconstruct a minimal Connection for the close event
			select {
			case events <- Event{
				Timestamp: now,
				Type:      EventConnectionClosed,
				Connection: types.Connection{
					LocalIP:    net.ParseIP(key.LocalIP),
					LocalPort:  key.LocalPort,
					RemoteIP:   net.ParseIP(key.RemoteIP),
					RemotePort: key.RemotePort,
					PID:        key.PID,
				},
			}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func rawToConnection(raw process.RawConnection, inodeToPID map[uint64]int, now time.Time) types.Connection {
	pid := inodeToPID[raw.Inode]
	procName := ""
	if pid > 0 {
		name, err := process.ProcessName(pid)
		if err == nil {
			procName = name
		}
	}

	localIP := net.ParseIP(process.HexToIP(raw.LocalIP))
	remoteIP := net.ParseIP(process.HexToIP(raw.RemoteIP))

	dir := types.DirectionUnknown
	if remoteIP != nil && !remoteIP.IsLoopback() && !remoteIP.IsPrivate() {
		dir = types.DirectionOutbound
	} else if remoteIP != nil && !remoteIP.IsUnspecified() {
		dir = types.DirectionInbound
	}

	return types.Connection{
		LocalIP:     localIP,
		LocalPort:   uint16(raw.LocalPort),
		RemoteIP:    remoteIP,
		RemotePort:  uint16(raw.RemotePort),
		PID:         pid,
		ProcessName: procName,
		Inode:       raw.Inode,
		State:       types.ConnectionState(raw.State),
		Direction:   dir,
		CreatedAt:   now,
	}
}
