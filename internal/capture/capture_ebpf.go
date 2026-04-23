//go:build bpf

package capture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/netbrother/netbrother/internal/process"
	"github.com/netbrother/netbrother/internal/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target x86_64 -I/usr/include/x86_64-linux-gnu" connect ./bpf/connect.c

const (
	eventConnect = 1
	eventAccept  = 2
	eventClose   = 3
)

func init() {
	ebpfDetect = probeBPF
	newEbpf = func() (Capturer, error) { return newEbpfCapturer() }
}

const bpfSyscall = 321 // __NR_bpf on x86_64

func probeBPF() bool {
	_, _, errno := syscall.Syscall(bpfSyscall, 0, 0, 0)
	return errno != syscall.ENOSYS
}

// bpfEvent matches the C struct event in bpf/connect.c.
type bpfEvent struct {
	Type     uint32
	PID      uint32
	TID      uint32
	Comm     [16]byte
	Family   uint16
	Sport    uint16
	DPort    uint16
	_        [2]byte // padding
	SAddrV4  uint32
	DAddrV4  uint32
	SAddrV6  [16]byte
	DAddrV6  [16]byte
	Inode    uint64
}

type bpfPidInfo struct {
	Pid  uint32
	Comm [16]byte
}

type ebpfCapturer struct {
	mu        sync.Mutex
	interval  time.Duration
	known     map[types.ConnectionKey]types.Connection
	inodeConn map[uint64]types.ConnectionKey // inode -> connection key for close matching
}

func newEbpfCapturer() (*ebpfCapturer, error) {
	return &ebpfCapturer{
		interval: 1 * time.Second,
		known:    make(map[types.ConnectionKey]types.Connection),
		inodeConn: make(map[uint64]types.ConnectionKey),
	}, nil
}

func (e *ebpfCapturer) Name() string        { return "ebpf" }
func (e *ebpfCapturer) RequiresRoot() bool    { return true }
func (e *ebpfCapturer) Close() error          { return nil }

func (e *ebpfCapturer) Start(ctx context.Context) (<-chan Event, error) {
	var objs connectObjects
	if err := loadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}

	// Attach fentry/fexit programs
	links := []link.Link{}

	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TcpConnect,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach fentry/tcp_connect: %w", err)
	}
	links = append(links, lnk)

	lnk, err = link.AttachTracing(link.TracingOptions{
		Program: objs.TcpClose,
	})
	if err != nil {
		for _, l := range links { l.Close() }
		objs.Close()
		return nil, fmt.Errorf("attach fentry/tcp_close: %w", err)
	}
	links = append(links, lnk)

	lnk, err = link.AttachTracing(link.TracingOptions{
		Program: objs.InetCskAccept,
	})
	if err != nil {
		// Accept is best-effort — inbound monitoring may not be available
		// on all kernels. Non-fatal.
	} else {
		links = append(links, lnk)
	}

	rd, err := perf.NewReader(objs.Events, 8192)
	if err != nil {
		for _, l := range links { l.Close() }
		objs.Close()
		return nil, fmt.Errorf("perf reader: %w", err)
	}

	events := make(chan Event)
	go e.run(ctx, events, rd, &objs, links)
	return events, nil
}

func (e *ebpfCapturer) run(ctx context.Context, events chan<- Event, rd *perf.Reader, objs *connectObjects, links []link.Link) {
	defer rd.Close()
	for _, l := range links { l.Close() }
	defer objs.Close()
	defer close(events)

	// Set a short deadline so Read() doesn't block forever
	rd.SetDeadline(time.Now().Add(100 * time.Millisecond))

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read BPF perf events (non-blocking due to short deadline)
		e.drainRingBuf(ctx, events, rd, objs)

		// Periodically poll /proc/net/tcp for state tracking
		select {
		case <-ticker.C:
			e.syncProc(ctx, events, objs)
		default:
		}
	}
}

func (e *ebpfCapturer) drainRingBuf(ctx context.Context, events chan<- Event, rd *perf.Reader, objs *connectObjects) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			// Reset deadline for next batch
			rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
			return
		}
		if record.LostSamples > 0 {
			continue
		}

		evt := e.parseBPFEvent(record.RawSample, objs)
		if evt == nil {
			continue
		}

		select {
		case events <- *evt:
		case <-ctx.Done():
			return
		}
	}
}

func (e *ebpfCapturer) syncProc(ctx context.Context, events chan<- Event, objs *connectObjects) {
	rawConns, err := process.ListTCPConnections()
	if err != nil {
		return
	}

	// Build inode->PID from BPF map (survives TIME_WAIT, process exit, /proc hiding)
	bpfInodePID := make(map[uint64]int)
	bpfInodeComm := make(map[uint64]string)
	var info bpfPidInfo
	for _, raw := range rawConns {
		inode := raw.Inode
		if inode == 0 {
			continue
		}
		if _, ok := bpfInodePID[inode]; ok {
			continue
		}
		if err := objs.PidByInode.Lookup(inode, &info); err == nil {
			bpfInodePID[inode] = int(info.Pid)
			bpfInodeComm[inode] = trimStr(info.Comm[:])
		}
	}

	// Also get /proc PIDs as fallback
	pidMap, _ := process.AllPIDsWithFds()
	procInodePID := make(map[uint64]int, len(pidMap)*4)
	for pid, inodes := range pidMap {
		for _, inode := range inodes {
			procInodePID[inode] = pid
		}
	}

	// Merge: BPF map takes priority
	inodeToPID := make(map[uint64]int)
	inodeToName := make(map[uint64]string)
	for inode, pid := range bpfInodePID {
		inodeToPID[inode] = pid
	}
	for inode, name := range bpfInodeComm {
		inodeToName[inode] = name
	}
	for inode, pid := range procInodePID {
		if _, exists := inodeToPID[inode]; !exists {
			inodeToPID[inode] = pid
		}
	}

	now := time.Now()
	currentKeys := make(map[types.ConnectionKey]bool)

	e.mu.Lock()
	for _, raw := range rawConns {
		if raw.State == int(types.StateListen) {
			continue
		}

		conn := rawToConnection(raw, inodeToPID, now)
		if name, ok := inodeToName[raw.Inode]; ok && name != "" {
			conn.ProcessName = name
		} else if conn.PID > 0 && conn.ProcessName == "" {
			n, err := process.ProcessName(conn.PID)
			if err == nil {
				conn.ProcessName = n
			}
		}
		key := conn.Key()
		currentKeys[key] = true

		if _, exists := e.known[key]; !exists {
			e.known[key] = conn
			if conn.Inode > 0 {
				e.inodeConn[conn.Inode] = key
			}
			e.mu.Unlock()
			select {
			case events <- Event{Timestamp: now, Type: EventNewConnection, Connection: conn}:
			case <-ctx.Done():
				e.mu.Lock()
				return
			}
			e.mu.Lock()
		}
	}

	// Detect closed connections
	for key, conn := range e.known {
		if !currentKeys[key] {
			delete(e.known, key)
			if conn.Inode > 0 {
				delete(e.inodeConn, conn.Inode)
			}
			e.mu.Unlock()
			select {
			case events <- Event{Timestamp: now, Type: EventConnectionClosed, Connection: conn}:
			case <-ctx.Done():
				e.mu.Lock()
				return
			}
			e.mu.Lock()
		}
	}
	e.mu.Unlock()
}

func (e *ebpfCapturer) parseBPFEvent(sample []byte, objs *connectObjects) *Event {
	if len(sample) < int(unsafe.Sizeof(bpfEvent{})) {
		return nil
	}
	be := (*bpfEvent)(unsafe.Pointer(&sample[0]))

	now := time.Now()
	pid := int(be.PID)
	procName := trimStr(be.Comm[:])

	var localIP, remoteIP net.IP
	if be.Family == syscall.AF_INET {
		ip := make(net.IP, 4)
		ip[0] = byte(be.SAddrV4)
		ip[1] = byte(be.SAddrV4 >> 8)
		ip[2] = byte(be.SAddrV4 >> 16)
		ip[3] = byte(be.SAddrV4 >> 24)
		localIP = ip
		ip = make(net.IP, 4)
		ip[0] = byte(be.DAddrV4)
		ip[1] = byte(be.DAddrV4 >> 8)
		ip[2] = byte(be.DAddrV4 >> 16)
		ip[3] = byte(be.DAddrV4 >> 24)
		remoteIP = ip
	} else {
		localIP = make(net.IP, 16)
		copy(localIP, be.SAddrV6[:])
		remoteIP = make(net.IP, 16)
		copy(remoteIP, be.DAddrV6[:])
	}

	localPort := int(be.Sport)
	remotePort := int((be.DPort >> 8) | (be.DPort << 8))

	dir := types.DirectionOutbound
	if remoteIP != nil && (remoteIP.IsLoopback() || remoteIP.IsPrivate()) {
		dir = types.DirectionInbound
	}

	state := types.StateEstablished
	evtType := EventNewConnection
	if be.Type == eventClose {
		state = types.StateClose
		evtType = EventConnectionClosed
	}

	conn := types.Connection{
		LocalIP:     localIP,
		LocalPort:   uint16(localPort),
		RemoteIP:    remoteIP,
		RemotePort:  uint16(remotePort),
		PID:         pid,
		ProcessName: procName,
		Inode:       be.Inode,
		State:       state,
		Direction:   dir,
		CreatedAt:   now,
	}

	// For close events, try to find the original connection to preserve state
	if be.Type == eventClose {
		e.mu.Lock()
		if key, ok := e.inodeConn[be.Inode]; ok {
			if orig, exists := e.known[key]; exists {
				conn.ProcessName = orig.ProcessName
				conn.PID = orig.PID
				delete(e.known, key)
				delete(e.inodeConn, be.Inode)
			}
		}
		e.mu.Unlock()
	} else {
		// Store connection for future close matching
		key := conn.Key()
		e.mu.Lock()
		if _, exists := e.known[key]; !exists {
			e.known[key] = conn
			if be.Inode > 0 {
				e.inodeConn[be.Inode] = key
			}
		}
		e.mu.Unlock()
	}

	return &Event{
		Timestamp:  now,
		Type:       evtType,
		Connection: conn,
	}
}

func trimStr(b []byte) string {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return string(b[:i])
}
