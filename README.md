# netbrother

Real-time TCP connection monitor for CTF & malware analysis. Tracks every connection at process level and detects beacons, unknown processes, and suspicious endpoints.

```bash
# Quick start
sudo ./netbrother                     # TUI dashboard
./netbrother -mode log                # Scrollable log output
./netbrother -mode log -output conns.txt   # Save to file
```

## Capture Backends

| Backend | Build | Root | Priority | Description |
|---------|-------|------|----------|-------------|
| **eBPF** | `make build-bpf` | yes | 1st | fentry/fexit kernel tracing — connect/accept/close events, PID survives TIME_WAIT |
| **Netlink** | `make build` | no | 2nd | `NETLINK_INET_DIAG` — queries kernel TCP table directly, bypasses /proc tampering |
| **Proc** | `make build` | no | 3rd | Reads `/proc/net/tcp` + `/proc/<pid>/fd/` — zero dependencies, always works |
| **Pcap** | `make build-pcap` | yes | — | libpcap packet capture (requires CGO + libpcap-dev) |

The best available backend is selected automatically at startup. eBPF > Netlink > Proc.

## Features

**Three detection engines** run on every new connection:

| Detection | Severity | Description |
|-----------|----------|-------------|
| Periodic beacon | High | CV analysis of inter-connection intervals (threshold: 0.25) |
| New process | Medium | Alerts on first-seen PID or connection key |
| Suspicious port/IP | Medium/High | Flags known C2 ports & user-defined CIDR ranges |

Default suspicious ports: `4444, 1337, 31337, 6660-6669, 5555, 7777, 8888, 9999`

**Two display modes:**

- **TUI** (`-mode tui`) — real-time dashboard with keyboard controls, filter, alerts panel
- **Log** (`-mode log`) — streaming table output to stdout, optionally to file with `-output`

## Flags

```
-mode string        Display mode: tui | log (default "tui")
-rate duration      Polling interval (default 1s)
-keep               Keep closed connections visible in TUI
-show-time-wait     Show TIME_WAIT connections (hidden by default)
-output string      Save unique connections to file
-bad-ports string   Extra suspicious ports (e.g. "4444,1337,6660-6669")
-bad-ips string     CIDR ranges to flag (e.g. "10.0.0.0/8")
-window duration    Sliding window for beacon detection (default 5m)
-min-samples int    Min samples before beacon detection activates (default 3)
-cv-threshold float CV threshold for beacon detection (default 0.25)
-i string           Network interface for pcap mode (default "eth0")
-v                  Verbose logging
-version            Print version & available backends
```

## Build

```bash
make build           # Pure Go, no CGO (netlink + proc backends)
make build-bpf       # + eBPF (requires clang + kernel BTF)
make build-pcap      # + libpcap (requires CGO + libpcap-dev)
make build-static    # Static build with pcap
```

## Examples

```bash
# CTF: monitor for beaconing implants
sudo ./netbrother -bad-ports "4444,1337,9001" -bad-ips "10.0.0.0/8"

# Log mode + file output for post-analysis
./netbrother -mode log -output capture.log

# Simulate a beacon to test detection
while true; do nc -z example.com 80; sleep 5; done

# eBPF mode for maximum visibility (kernel-level tracing)
make build-bpf && sudo ./netbrother-bpf -mode log -v
```

## TUI Controls

| Key | Action |
|-----|--------|
| `q` | Quit |
| `j`/`↓` `k`/`↑` | Scroll |
| `g` `G` | Top / Bottom |
| `/` | Filter by process, IP, port, or PID |
| `a` | Toggle alerts panel |
| `t` | Toggle TIME_WAIT visibility |
| `ESC` | Cancel filter |

## Detection Details

**Periodic beacon detection** tracks intervals between successive connections from the same (PID, RemoteIP, RemotePort). Uses coefficient of variation (CV = stddev/mean) — CV ≤ 0.25 indicates a regular pattern. Example alert: `PID 1234 (nc) -> 10.0.0.5:4444 every ~30s (CV=0.12)`
