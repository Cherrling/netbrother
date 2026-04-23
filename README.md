# netbrother

A real-time network connection monitor for Linux, designed for CTF competitions and malware analysis. Tracks every TCP connection at the process level and automatically detects suspicious behavior — periodic beacons, unknown processes, connections to suspicious ports/IPs.

## Quick start

```bash
# Build (pure Go, no dependencies)
make build

# Run TUI (default)
sudo ./netbrother

# Or log mode (scrolls to stdout)
./netbrother -mode log

# Save all connections to a file
./netbrother -output connections.txt
```

## Features

### Process-level connection monitoring
- Reads `/proc/net/tcp` + `/proc/<pid>/fd/` — no kernel modules, no dependencies
- Resolves PID, process name, and executable path for every connection
- Inode-to-PID cache survives TIME_WAIT (remembers PIDs even after the process closes the socket)

### Three detection engines

| Detection | Description | Severity |
|---|---|---|
| **Periodic beacon** | Detects connections at regular intervals (CV analysis on inter-arrival times) | HIGH |
| **New process** | Alerts when a never-before-seen process makes a connection | MED |
| **Suspicious port/IP** | Flags connections to known C2 ports (4444, 1337, 31337, 6660-6669, etc.) | MED/HIGH |

### Dual display modes

**TUI mode** (`-mode tui`): Real-time dashboard with keyboard controls

```
┌──────────────────────────────────────────────────────────────────┐
│ netbrother | conns: 23 (hide TIME_WAIT) | alerts: 4             │
├──────────┬────────────────────┬──────────────────────┬──────────┤
│     PID  │ PROC               │ LOCAL                │ REMOTE   │
├──────────┼────────────────────┼──────────────────────┼──────────┤
│    2911  │ qbittorrent-nox    │ 192.168.9.107:44514  │ 13.2...  │
│ 3364243  │ sshd-session       │ 100.118.229.103:22   │ 100....  │
│ 3929881  │ claude             │ 192.168.9.107:40764  │ 116....  │
├──────────┴────────────────────┴──────────────────────┴──────────┤
│ [q] quit  [/] filter  [j/k/arrows] scroll  [a] alerts  [t] tw  │
└──────────────────────────────────────────────────────────────────┘
```

**Log mode** (`-mode log`): Scrolls new connections as they appear

```
LOCAL                   REMOTE                  PID       PROC                  EXE
----------------------  ----------------------  --------  --------------------  --------
192.168.9.107:44514     13.226.69.71:1337       2911      qbittorrent-nox       /usr/bin/qbittorrent-nox
100.118.229.103:22      100.105.34.127:60276    3364243   sshd-session          /usr/lib/openssh/sshd-session
127.0.0.1:36690         127.0.0.1:9100          2253      prometheus            /opt/grafana/prometheus/prometheus
```

### Output file
Use `-output <file>` to save every unique connection to a file (same table format, deduplicated).

## Usage

```
netbrother [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-mode` | `tui` | Display mode: `tui` or `log` |
| `-i` | `eth0` | Network interface (for pcap mode) |
| `-rate` | `1s` | Polling interval for /proc mode |
| `-keep` | `false` | Keep closed connections visible in TUI (marked as CLOSE) |
| `-show-time-wait` | `false` | Show TIME_WAIT connections (hidden by default) |
| `-output` | `""` | Save all unique connections to file (table format) |
| `-bad-ports` | see below | Extra port ranges to flag (e.g. `4444,1337,6660-6669`) |
| `-bad-ips` | `""` | CIDR ranges to flag (e.g. `10.0.0.0/8`) |
| `-window` | `5m` | Sliding window for periodic beacon detection |
| `-min-samples` | `3` | Minimum samples before beacon detection activates |
| `-cv-threshold` | `0.25` | Max coefficient of variation for beacon detection |
| `-v` | `false` | Verbose logging (shows capture backend) |
| `-version` | `false` | Print version and exit |

Default suspicious ports: `4444, 1337, 31337, 6660-6669, 5555, 7777, 8888, 9999`

## TUI key bindings

| Key | Action |
|---|---|
| `q` | Quit |
| `j` / `↓` | Scroll down |
| `k` / `↑` | Scroll up |
| `g` | Jump to top |
| `G` | Jump to bottom |
| `/` | Filter (by process name, remote IP, port, or PID) |
| `a` | Toggle alerts panel |
| `t` | Toggle TIME_WAIT visibility |
| `ESC` | Cancel filter |

## Build

```bash
# Pure Go build (recommended, no CGO needed)
make build

# With pcap support (requires libpcap-dev)
make build-pcap

# Static build with pcap
make build-static
```

The default build uses `/proc` capture (zero dependencies, always works). The pcap build adds libpcap-based packet capture (requires root, needs `libpcap-dev`).

## Detection details

### Periodic beacon detection
Tracks the interval between consecutive connections from the same (PID, RemoteIP, RemotePort). Uses the coefficient of variation (CV = stddev/mean) to measure regularity. CV ≤ 0.25 means the connection pattern is regular enough to be suspicious.

Example alert: `PID 1234 (nc) -> 10.0.0.5:4444 every ~30s (CV=0.12)`

### New process detection
Maintains a set of seen PIDs and connection keys. The first connection from a new process triggers an alert, which helps catch short-lived processes that spawn and connect before you can inspect them.

### Suspicious port/IP detection
Flags connections to known C2/backdoor ports and any user-specified CIDR ranges. Useful for quickly spotting reverse shells and beacon traffic.

## Examples

```bash
# Monitor in TUI, keeping closed connections visible
sudo ./netbrother -keep

# Scroll to stdout, save everything to a file
./netbrother -mode log -output connections.txt

# Show TIME_WAIT connections too
./netbrother -show-time-wait

# Flag custom bad ports
./netbrother -bad-ports "4444,1337,6660-6669,9001"

# Flag connections to a suspicious subnet
sudo ./netbrother -bad-ips "10.0.0.0/8,192.168.0.0/16"

# Simulate a beacon to test detection:
# (in another terminal)
while true; do nc -z example.com 80; sleep 5; done
```

## How it works

1. **Capture**: Reads `/proc/net/tcp` for all TCP connections and `/proc/<pid>/fd/` to map socket inodes to PIDs
2. **Detect**: Runs three detection engines against each new connection
3. **Display**: Renders in TUI or log mode, optionally writes to file

No kernel modules, no BPF, no packet capture required (unless you build with pcap).
