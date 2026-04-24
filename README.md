# netbrother

实时 TCP 连接监控工具，适用于 CTF 竞赛和恶意软件分析。追踪每个进程的网络连接，自动检测异常行为。

```bash
# 快速开始
sudo ./netbrother                     # TUI 仪表盘
./netbrother -mode log                # 滚动日志输出
./netbrother -mode log -output conns.txt   # 保存到文件
```

## 捕获后端

| 后端 | 构建方式 | Root | 优先级 | 说明 |
|---------|-------|------|----------|------|
| **eBPF** | `make build-bpf` | 需要 | 1 | fentry/fexit 内核追踪，PID 跨 TIME_WAIT 持久化 |
| **Netlink** | `make build` | 否 | 2 | 直接查询内核 TCP 表，绕过 /proc 篡改 |
| **Proc** | `make build` | 否 | 3 | 读取 `/proc/net/tcp`，零依赖兜底 |
| **Pcap** | `make build-pcap` | 需要 | — | libpcap 数据包抓取（需 CGO + libpcap-dev） |

启动时自动选择最优后端：eBPF > Netlink > Proc。

## 检测引擎

| 检测 | 严重级别 | 说明 |
|-----------|----------|------|
| 周期性回连 | 高 | 对连接间隔做变异系数分析（阈值 0.25） |
| 新进程 | 中 | 首次出现的 PID 或连接触发告警 |
| 可疑端口/IP | 中/高 | 标记已知 C2 端口和用户指定的 CIDR 范围 |

默认可疑端口：`4444, 1337, 31337, 6660-6669, 5555, 7777, 8888, 9999`

## 参数

```
-mode string        显示模式: tui | log（默认 "tui"）
-rate duration      轮询间隔（默认 1s）
-keep               TUI 中保留已关闭连接
-show-time-wait     显示 TIME_WAIT 连接（默认隐藏）
-output string      保存连接到文件
-bad-ports string   额外可疑端口（如 "4444,1337,6660-6669"）
-bad-ips string     标记的 CIDR 范围（如 "10.0.0.0/8"）
-window duration    回连检测滑动窗口（默认 5m）
-min-samples int    回连检测最小样本数（默认 3）
-cv-threshold float 回连检测 CV 阈值（默认 0.25）
-i string           pcap 模式的网卡（默认 "eth0"）
-v                  详细日志
-version            打印版本和可用后端
```

## 构建

```bash
make build           # 纯 Go，无 CGO（netlink + proc）
make build-bpf       # + eBPF（需 clang + 内核 BTF）
make build-pcap      # + libpcap（需 CGO + libpcap-dev）
```

## 使用示例

```bash
# CTF：监控潜在的回连木马
sudo ./netbrother -bad-ports "4444,1337,9001" -bad-ips "10.0.0.0/8"

# 日志模式 + 保存到文件供后续分析
./netbrother -mode log -output capture.log

# 模拟回连测试检测效果
while true; do nc -z example.com 80; sleep 5; done

# eBPF 模式，最大可见性
make build-bpf && sudo ./netbrother-bpf -mode log -v
```

## TUI 快捷键

| 按键 | 操作 |
|-----|------|
| `q` | 退出 |
| `j`/`↓` `k`/`↑` | 滚动 |
| `g` `G` | 顶部 / 底部 |
| `/` | 过滤（进程、IP、端口、PID） |
| `a` | 切换告警面板 |
| `t` | 切换 TIME_WAIT 可见性 |
| `ESC` | 取消过滤 |

## 检测原理

**周期性回连检测**：追踪同一 (PID, RemoteIP, RemotePort) 连续连接的时间间隔，计算变异系数 CV = 标准差/均值。CV ≤ 0.25 视为规律连接。告警示例：`PID 1234 (nc) -> 10.0.0.5:4444 每 ~30s 连接一次 (CV=0.12)`
