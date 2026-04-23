package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// RawConnection is an unparsed entry from /proc/net/tcp or /proc/net/tcp6.
type RawConnection struct {
	Slot       int
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      int
	Inode      uint64
}

// hexToIP converts a big-endian hex IP string to dotted-decimal notation.
// /proc/net/tcp stores IPs as 4-byte hex in network byte order.
func hexToIP(hex string) string {
	if len(hex) == 8 {
		// IPv4: 0100007F -> 127.0.0.1
		n, _ := strconv.ParseUint(hex, 16, 32)
		return fmt.Sprintf("%d.%d.%d.%d",
			byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	}
	if len(hex) == 32 {
		// IPv6: groups of 4 hex chars, big-endian 16-bit groups
		var parts []string
		for i := 0; i < 32; i += 4 {
			// /proc/net/tcp6 stores in big-endian 16-bit groups,
			// but the groups themselves are in network byte order.
			// We need to reverse each 4-hex-char group.
			group := hex[i : i+4]
			parts = append(parts, group)
		}
		// Reorder: groups are stored in network byte order (big-endian),
		// so for IPv6 the groups are: [0:4][4:8][8:12][12:16][16:20][20:24][24:28][28:32]
		// which is already the correct IPv6 group order.
		// But each 16-bit group within the 32-bit pair is byte-swapped.
		// Actually in /proc/net/tcp6, the address is stored as 4 x 32-bit big-endian,
		// so we need to read 8 hex chars at a time.
		return expandIPv6(hex)
	}
	return hex
}

func expandIPv6(hex string) string {
	// /proc/net/tcp6 stores IPv6 addresses as 4 x 32-bit big-endian hex values
	// Each 32-bit value is 8 hex chars, stored in network byte order.
	// So the 32 hex chars represent 4 groups of 8 hex chars.
	if len(hex) < 32 {
		return hex
	}
	var groups []string
	for i := 0; i < 32; i += 8 {
		// Each 8-char group is a 32-bit big-endian value
		// Split into two 16-bit parts
		part := hex[i : i+8]
		if part == "00000000" {
			groups = append(groups, "0")
		} else {
			groups = append(groups, strings.TrimLeft(part, "0"))
		}
	}
	// Try to compact IPv6
	joined := strings.Join(groups, ":")
	return joined
}

// parseProcNetLine parses a single line from /proc/net/tcp or /proc/net/tcp6.
// Format (whitespace-separated):
//
//	sl local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode
//
// Example:
//
//	0: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
func parseProcNetLine(line string) (RawConnection, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return RawConnection{}, false
	}

	// Parse slot
	slotStr := strings.TrimSuffix(fields[0], ":")
	slot, err := strconv.Atoi(slotStr)
	if err != nil {
		return RawConnection{}, false
	}

	// Parse local address: HEX_IP:PORT
	localParts := strings.SplitN(fields[1], ":", 2)
	if len(localParts) != 2 {
		return RawConnection{}, false
	}
	localPort, _ := strconv.ParseInt(localParts[1], 16, 32)

	// Parse remote address
	remoteParts := strings.SplitN(fields[2], ":", 2)
	if len(remoteParts) != 2 {
		return RawConnection{}, false
	}
	remotePort, _ := strconv.ParseInt(remoteParts[1], 16, 32)

	// Parse state
	state, _ := strconv.ParseInt(fields[3], 16, 32)

	// Parse inode
	inode, _ := strconv.ParseUint(fields[9], 10, 64)

	return RawConnection{
		Slot:       slot,
		LocalIP:    localParts[0],
		LocalPort:  int(localPort),
		RemoteIP:   remoteParts[0],
		RemotePort: int(remotePort),
		State:      int(state),
		Inode:      inode,
	}, true
}

// readProcNetFile reads and parses a /proc/net/* file.
func readProcNetFile(path string) ([]RawConnection, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var conns []RawConnection
	for _, line := range lines[1:] { // skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if c, ok := parseProcNetLine(line); ok {
			conns = append(conns, c)
		}
	}
	return conns, nil
}

// ListTCPConnections parses /proc/net/tcp and /proc/net/tcp6.
func ListTCPConnections() ([]RawConnection, error) {
	var all []RawConnection

	v4, err := readProcNetFile("/proc/net/tcp")
	if err == nil {
		all = append(all, v4...)
	}

	v6, err := readProcNetFile("/proc/net/tcp6")
	if err == nil {
		all = append(all, v6...)
	}

	return all, nil
}

// ResolvePIDByInode finds the PID that owns a given socket inode.
func ResolvePIDByInode(inode uint64) (int, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return 0, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry, "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fdEntries {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Socket links look like: socket:[12345]
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				sockInodeStr := link[len("socket:[") : len(link)-1]
				sockInode, _ := strconv.ParseUint(sockInodeStr, 10, 64)
				if sockInode == inode {
					return pid, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("inode %d not found in any process", inode)
}

// ProcessName returns the process name for a given PID.
func ProcessName(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// AllPIDsWithFds returns all PIDs that have open sockets.
// Returns a map of PID -> list of socket inodes.
func AllPIDsWithFds() (map[int][]uint64, error) {
	result := make(map[int][]uint64)

	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry, "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		var inodes []uint64
		for _, fd := range fdEntries {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				sockInodeStr := link[len("socket:[") : len(link)-1]
				sockInode, _ := strconv.ParseUint(sockInodeStr, 10, 64)
				if sockInode > 0 {
					inodes = append(inodes, sockInode)
				}
			}
		}
		if len(inodes) > 0 {
			result[pid] = inodes
		}
	}

	return result, nil
}
