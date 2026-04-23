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
	inodePID  map[uint64]int               // cache: socket inode -> PID (survives TIME_WAIT)
}

func newProcCapturer() (*procCapturer, error) {
	return &procCapturer{
		interval: 1 * time.Second,
		known:    make(map[types.ConnectionKey]bool),
		inodePID: make(map[uint64]int),
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

	// Build fresh inode -> PID map from /proc (expensive but accurate)
	pidMap, err := process.AllPIDsWithFds()
	if err != nil {
		return
	}
	liveInodePID := make(map[uint64]int, len(pidMap)*4)
	for pid, inodes := range pidMap {
		for _, inode := range inodes {
			liveInodePID[inode] = pid
		}
	}

	// Merge live data into cache (update cache with fresh mappings)
	p.mu.Lock()
	for inode, pid := range liveInodePID {
		p.inodePID[inode] = pid
	}
	// Build final lookup: live first, then cache as fallback
	inodeToPID := make(map[uint64]int, len(liveInodePID)+len(p.inodePID))
	for inode, pid := range liveInodePID {
		inodeToPID[inode] = pid
	}
	for inode, pid := range p.inodePID {
		if _, ok := liveInodePID[inode]; !ok {
			inodeToPID[inode] = pid
		}
	}
	p.mu.Unlock()

	currentKeys := make(map[types.ConnectionKey]bool)
	var newConns []types.Connection

	for _, raw := range rawConns {
		if raw.State == int(types.StateListen) {
			continue
		}

		conn := rawToConnection(raw, inodeToPID, now)
		key := conn.Key()
		currentKeys[key] = true

		p.mu.Lock()
		if !p.known[key] {
			p.known[key] = true
			newConns = append(newConns, conn)
			if conn.PID > 0 {
				p.inodePID[raw.Inode] = conn.PID
			}
		}
		p.mu.Unlock()
	}

	for _, conn := range newConns {
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

	// Detect closed connections (collect under lock, emit outside)
	var closedKeys []types.ConnectionKey
	p.mu.Lock()
	for key := range p.known {
		if !currentKeys[key] {
			delete(p.known, key)
			closedKeys = append(closedKeys, key)
		}
	}
	p.mu.Unlock()

	for _, key := range closedKeys {
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
