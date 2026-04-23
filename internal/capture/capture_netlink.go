package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/netbrother/netbrother/internal/process"
	"github.com/netbrother/netbrother/internal/types"
)

const (
	sockDiagByFamily = 20
	nlmFRequest      = 0x1
	nlmFDump         = 0x300
)

func init() {
	netlinkDetect = func() bool {
		fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
		if err != nil {
			return false
		}
		syscall.Close(fd)
		return true
	}
	newNetlink = func() (Capturer, error) {
		return newNetlinkCapturer(), nil
	}
}

// inetDiagReqV2 matches kernel struct inet_diag_req_v2 (56 bytes on amd64).
// Fields are laid out to match the C struct without padding.
type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	SrcPort  uint16
	DstPort  uint16
	Src      [4]uint32
	Dst      [4]uint32
	If       uint32
	Cookie   [2]uint32
}

// inetDiagMsg matches kernel struct inet_diag_msg (72 bytes on amd64).
type inetDiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	SrcPort uint16
	DstPort uint16
	Src     [4]uint32
	Dst     [4]uint32
	If      uint32
	Cookie  [2]uint32
	Expires uint32
	Rqueue  uint32
	Wqueue  uint32
	Uid     uint32
	Inode   uint32
}

type netlinkCapturer struct {
	mu       sync.Mutex
	interval time.Duration
	known    map[types.ConnectionKey]types.Connection
	inodePID map[uint64]int
}

func newNetlinkCapturer() *netlinkCapturer {
	return &netlinkCapturer{
		interval: 1 * time.Second,
		known:    make(map[types.ConnectionKey]types.Connection),
		inodePID: make(map[uint64]int),
	}
}

func (n *netlinkCapturer) Name() string  { return "netlink" }
func (n *netlinkCapturer) RequiresRoot() bool { return false }

func (n *netlinkCapturer) Close() error { return nil }

func (n *netlinkCapturer) Start(ctx context.Context) (<-chan Event, error) {
	events := make(chan Event)
	go n.poll(ctx, events)
	return events, nil
}

func (n *netlinkCapturer) poll(ctx context.Context, events chan<- Event) {
	defer close(events)

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()

	n.scanAndEmit(ctx, events)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.scanAndEmit(ctx, events)
		}
	}
}

func (n *netlinkCapturer) scanAndEmit(ctx context.Context, events chan<- Event) {
	now := time.Now()

	conns, err := n.dumpTCP()
	if err != nil {
		return
	}

	// Build inode→PID map from /proc (best-effort)
	pidMap, err := process.AllPIDsWithFds()
	if err != nil {
		pidMap = nil
	}
	n.mu.Lock()
	liveInodePID := make(map[uint64]int, len(pidMap)*4)
	for pid, inodes := range pidMap {
		for _, inode := range inodes {
			liveInodePID[inode] = pid
		}
	}
	// Merge cached inode→PID (survives TIME_WAIT)
	for inode, pid := range liveInodePID {
		n.inodePID[inode] = pid
	}
	inodeToPID := make(map[uint64]int, len(liveInodePID)+len(n.inodePID))
	for inode, pid := range liveInodePID {
		inodeToPID[inode] = pid
	}
	for inode, pid := range n.inodePID {
		if _, ok := liveInodePID[inode]; !ok {
			inodeToPID[inode] = pid
		}
	}
	n.mu.Unlock()

	// Resolve process names for PIDs
	procNameCache := make(map[int]string)

	currentKeys := make(map[types.ConnectionKey]bool)
	var newConns []types.Connection

	for _, raw := range conns {
		if raw.State == int(types.StateListen) {
			continue
		}

		conn := n.rawToConnection(raw, inodeToPID, procNameCache, now)
		key := conn.Key()
		currentKeys[key] = true

		n.mu.Lock()
		if _, exists := n.known[key]; !exists {
			n.known[key] = conn
			newConns = append(newConns, conn)
			if conn.PID > 0 {
				n.inodePID[raw.Inode] = conn.PID
			}
		}
		n.mu.Unlock()
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

	// Detect closed connections
	var closedEvents []Event
	n.mu.Lock()
	for key, conn := range n.known {
		if !currentKeys[key] {
			delete(n.known, key)
			closedEvents = append(closedEvents, Event{
				Timestamp:  now,
				Type:       EventConnectionClosed,
				Connection: conn,
			})
		}
	}
	n.mu.Unlock()

	for _, evt := range closedEvents {
		select {
		case events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

// netlinkConn is an intermediate representation parsed from inet_diag_msg.
type netlinkConn struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      int
	Inode      uint64
}

func (n *netlinkCapturer) dumpTCP() ([]netlinkConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	defer syscall.Close(fd)

	err = syscall.Bind(fd, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
	})
	if err != nil {
		return nil, fmt.Errorf("netlink bind: %w", err)
	}

	var all []netlinkConn

	for _, family := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		conns, err := n.dumpFamily(fd, family)
		if err != nil {
			continue
		}
		all = append(all, conns...)
	}

	return all, nil
}

func (n *netlinkCapturer) dumpFamily(fd int, family uint8) ([]netlinkConn, error) {
	// Build request: nlmsghdr + inet_diag_req_v2
	reqLen := int(unsafe.Sizeof(syscall.NlMsghdr{})) + int(unsafe.Sizeof(inetDiagReqV2{}))
	req := make([]byte, reqLen)
	native := binary.NativeEndian

	// nlmsghdr
	native.PutUint32(req[0:4], uint32(reqLen))
	native.PutUint16(req[4:6], sockDiagByFamily)
	native.PutUint16(req[6:8], nlmFRequest|nlmFDump)
	native.PutUint32(req[8:12], uint32(family))
	native.PutUint32(req[12:16], 0) // pid (0 = kernel)

	// inet_diag_req_v2
	req[16] = family
	req[17] = syscall.IPPROTO_TCP
	req[18] = 0 // ext
	req[19] = 0 // pad
	native.PutUint32(req[20:24], 0xFFFFFFFF) // all states
	// sockid (24-72): all zeros = match all

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return nil, fmt.Errorf("netlink sendto: %w", err)
	}

	// Read responses
	var conns []netlinkConn
	buf := make([]byte, 128*1024)

	for {
		nr, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return conns, fmt.Errorf("netlink recv: %w", err)
		}
		if nr == 0 {
			break
		}

		data := buf[:nr]
		msgs, done, err := parseNetlinkResponses(data, sockDiagByFamily)
		if err != nil {
			return conns, err
		}
		conns = append(conns, msgs...)
		if done {
			break
		}
	}

	return conns, nil
}

func parseNetlinkResponses(data []byte, expectType uint16) ([]netlinkConn, bool, error) {
	var conns []netlinkConn

	for len(data) >= int(unsafe.Sizeof(syscall.NlMsghdr{})) {
		hdrLen := int(unsafe.Sizeof(syscall.NlMsghdr{}))
		if len(data) < hdrLen {
			break
		}

		native := binary.NativeEndian
		msgLen := native.Uint32(data[0:4])
		msgType := native.Uint16(data[4:6])

		if msgLen < uint32(hdrLen) || uint32(len(data)) < msgLen {
			break
		}

		switch msgType {
		case syscall.NLMSG_DONE:
			return conns, true, nil

		case syscall.NLMSG_ERROR:
			// nlmsgerr is at offset hdrLen, but we can just check the error code
			if msgLen >= uint32(hdrLen+4) {
				errCode := int32(native.Uint32(data[hdrLen : hdrLen+4]))
				if errCode != 0 {
					return conns, true, fmt.Errorf("netlink error: %s", syscall.Errno(-errCode))
				}
			}
			return conns, true, nil

		case uint16(sockDiagByFamily):
			if msgLen < uint32(hdrLen+int(unsafe.Sizeof(inetDiagMsg{}))) {
				break
			}
			conn := parseInetDiagMsg(data[hdrLen:])
			conns = append(conns, conn)

		default:
			// Unknown message type, skip
		}

		// Advance to next message (NLMSG_ALIGN)
		aligned := (msgLen + 3) & ^uint32(3)
		data = data[aligned:]
	}

	return conns, false, nil
}

func parseInetDiagMsg(data []byte) netlinkConn {
	family := data[0]
	state := data[1]

	srcPort := binary.BigEndian.Uint16(data[4:6])
	dstPort := binary.BigEndian.Uint16(data[6:8])

	var localIP, remoteIP net.IP
	if family == syscall.AF_INET {
		ip := make(net.IP, 4)
		copy(ip, data[8:12])
		localIP = ip
		ip = make(net.IP, 4)
		copy(ip, data[24:28])
		remoteIP = ip
	} else {
		ip := make(net.IP, 16)
		copy(ip, data[8:24])
		localIP = ip
		ip = make(net.IP, 16)
		copy(ip, data[24:40])
		remoteIP = ip
	}

	inode := uint64(binary.NativeEndian.Uint32(data[68:72]))

	return netlinkConn{
		LocalIP:    localIP,
		LocalPort:  int(srcPort),
		RemoteIP:   remoteIP,
		RemotePort: int(dstPort),
		State:      int(state),
		Inode:      inode,
	}
}

func (n *netlinkCapturer) rawToConnection(raw netlinkConn, inodeToPID map[uint64]int, nameCache map[int]string, now time.Time) types.Connection {
	pid := inodeToPID[raw.Inode]

	procName := ""
	if pid > 0 {
		if name, ok := nameCache[pid]; ok {
			procName = name
		} else {
			name, err := process.ProcessName(pid)
			if err == nil {
				procName = name
				nameCache[pid] = name
			}
		}
	}

	dir := types.DirectionUnknown
	if raw.RemoteIP != nil && !raw.RemoteIP.IsLoopback() && !raw.RemoteIP.IsPrivate() {
		dir = types.DirectionOutbound
	} else if raw.RemoteIP != nil && !raw.RemoteIP.IsUnspecified() {
		dir = types.DirectionInbound
	}

	return types.Connection{
		LocalIP:     raw.LocalIP,
		LocalPort:   uint16(raw.LocalPort),
		RemoteIP:    raw.RemoteIP,
		RemotePort:  uint16(raw.RemotePort),
		PID:         pid,
		ProcessName: procName,
		Inode:       raw.Inode,
		State:       types.ConnectionState(raw.State),
		Direction:   dir,
		CreatedAt:   now,
	}
}
