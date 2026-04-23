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
	"github.com/netbrother/netbrother/internal/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target x86_64 -I/usr/include/x86_64-linux-gnu" connect ./bpf/connect.c

func init() {
	ebpfDetect = func() bool {
		return probeBPF()
	}
	newEbpf = func() (Capturer, error) {
		return newEbpfCapturer()
	}
}

const bpfSyscall = 321 // __NR_bpf on x86_64

func probeBPF() bool {
	_, _, errno := syscall.Syscall(bpfSyscall, 0, 0, 0)
	return errno != syscall.ENOSYS
}

type ebpfConnKey struct {
	DestIP   string
	DestPort uint16
	PID      int
}

type ebpfCapturer struct {
	mu       sync.Mutex
	interval time.Duration
	known    map[types.ConnectionKey]types.Connection
	conns    map[types.ConnectionKey]types.Connection
	pidCache map[ebpfConnKey]int
}

func newEbpfCapturer() (*ebpfCapturer, error) {
	return &ebpfCapturer{
		interval: 1 * time.Second,
		known:    make(map[types.ConnectionKey]types.Connection),
		conns:    make(map[types.ConnectionKey]types.Connection),
		pidCache: make(map[ebpfConnKey]int),
	}, nil
}

func (e *ebpfCapturer) Name() string         { return "ebpf" }
func (e *ebpfCapturer) RequiresRoot() bool     { return true }
func (e *ebpfCapturer) Close() error           { return nil }

// connectEvent matches the C struct in bpf/connect.c.
type connectEvent struct {
	PID      uint64
	TID      uint32
	Comm     [16]byte
	Family   uint16
	Sport    uint16 // local port (host byte order)
	DPort    uint16 // dest port (network byte order)
	SAddrV4  uint32
	DAddrV4  uint32
	SAddrV6  [16]byte
	DAddrV6  [16]byte
	Inode    uint64
}

func (e *ebpfCapturer) Start(ctx context.Context) (<-chan Event, error) {
	var objs connectObjects
	if err := loadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}

	tp, err := link.Kprobe("tcp_connect", objs.KprobeTcpConnect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("perf reader: %w", err)
	}

	events := make(chan Event)
	go e.poll(ctx, events, rd, tp, &objs)
	return events, nil
}

func (e *ebpfCapturer) poll(ctx context.Context, events chan<- Event, rd *perf.Reader, tp link.Link, objs *connectObjects) {
	defer rd.Close()
	defer tp.Close()
	defer objs.Close()
	defer close(events)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			return
		}
		if record.LostSamples > 0 {
			continue
		}

		evt := e.parseEvent(record.RawSample)
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

func (e *ebpfCapturer) parseEvent(sample []byte) *Event {
	if len(sample) < int(unsafe.Sizeof(connectEvent{})) {
		return nil
	}

	ce := (*connectEvent)(unsafe.Pointer(&sample[0]))
	now := time.Now()

	pid := int(ce.PID)
	procName := string(ce.Comm[:trimLen(ce.Comm[:])])

	var localIP, remoteIP net.IP
	var localPort, remotePort int

	if ce.Family == syscall.AF_INET {
		ip := make(net.IP, 4)
		// skc_rcv_saddr and skc_daddr are in network byte order
		ip[0] = byte(ce.SAddrV4)
		ip[1] = byte(ce.SAddrV4 >> 8)
		ip[2] = byte(ce.SAddrV4 >> 16)
		ip[3] = byte(ce.SAddrV4 >> 24)
		localIP = ip

		ip = make(net.IP, 4)
		ip[0] = byte(ce.DAddrV4)
		ip[1] = byte(ce.DAddrV4 >> 8)
		ip[2] = byte(ce.DAddrV4 >> 16)
		ip[3] = byte(ce.DAddrV4 >> 24)
		remoteIP = ip
	} else {
		localIP = make(net.IP, 16)
		copy(localIP, ce.SAddrV6[:])
		remoteIP = make(net.IP, 16)
		copy(remoteIP, ce.DAddrV6[:])
	}

	// skc_dport is __be16; swap bytes on little-endian
	localPort = int(ce.Sport)
	remotePort = int((ce.DPort >> 8) | (ce.DPort << 8))

	dir := types.DirectionOutbound
	if remoteIP != nil && (remoteIP.IsLoopback() || remoteIP.IsPrivate()) {
		dir = types.DirectionInbound
	}

	conn := types.Connection{
		LocalIP:     localIP,
		LocalPort:   uint16(localPort),
		RemoteIP:    remoteIP,
		RemotePort:  uint16(remotePort),
		PID:         pid,
		ProcessName: procName,
		Inode:       ce.Inode,
		State:       types.StateEstablished,
		Direction:   dir,
		CreatedAt:   now,
	}

	return &Event{
		Timestamp:  now,
		Type:       EventNewConnection,
		Connection: conn,
	}
}

func trimLen(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return len(b)
}
