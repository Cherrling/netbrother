//go:build !nopcap

package capture

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/netbrother/netbrother/internal/types"
)

func init() {
	pcapDetect = func() bool {
		// Check if any interfaces are available for capture
		ifaces, err := pcap.FindAllDevs()
		return err == nil && len(ifaces) > 0
	}
	newPcap = newPcapCapturer
}

type pcapCapturer struct {
	iface      string
	snapLen    int32
	promisc    bool
	timeout    time.Duration
	handle     *pcap.Handle
}

func newPcapCapturer(iface string) (*pcapCapturer, error) {
	return &pcapCapturer{
		iface:   iface,
		snapLen: 65536,
		promisc: false,
		timeout: time.Second,
	}, nil
}

func (p *pcapCapturer) Name() string {
	return "pcap"
}

func (p *pcapCapturer) RequiresRoot() bool {
	return true
}

func (p *pcapCapturer) Close() error {
	if p.handle != nil {
		p.handle.Close()
	}
	return nil
}

func (p *pcapCapturer) Start(ctx context.Context) (<-chan Event, error) {
	handle, err := pcap.OpenLive(p.iface, p.snapLen, p.promisc, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}
	p.handle = handle

	// Use BPF filter to capture only TCP packets
	if err := handle.SetBPFFilter("tcp"); err != nil {
		return nil, fmt.Errorf("bpf filter: %w", err)
	}

	events := make(chan Event)
	go p.capture(ctx, handle, events)
	return events, nil
}

func (p *pcapCapturer) capture(ctx context.Context, handle *pcap.Handle, events chan<- Event) {
	defer close(events)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			p.processPacket(packet, events)
		}
	}
}

func (p *pcapCapturer) processPacket(packet gopacket.Packet, events chan<- Event) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp == nil {
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// Try IPv6
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}
	if ipLayer == nil {
		return
	}

	var srcIP, dstIP string
	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	case *layers.IPv6:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	default:
		return
	}

	// Determine event type based on TCP flags
	eventType := EventNewConnection
	if tcp.FIN || tcp.RST {
		eventType = EventConnectionClosed
	}

	// Determine direction
	dir := types.DirectionUnknown
	srcNet := net.ParseIP(srcIP)
	dstNet := net.ParseIP(dstIP)
	if dstNet != nil && !dstNet.IsLoopback() && !dstNet.IsPrivate() {
		dir = types.DirectionOutbound
	} else if dstNet != nil && !dstNet.IsUnspecified() {
		dir = types.DirectionInbound
	}

	conn := types.Connection{
		LocalIP:    srcNet,
		LocalPort:  uint16(tcp.SrcPort),
		RemoteIP:   dstNet,
		RemotePort: uint16(tcp.DstPort),
		State:      types.StateEstablished,
		Direction:  dir,
		CreatedAt:  time.Now(),
	}

	select {
	case events <- Event{
		Timestamp:  time.Now(),
		Type:       eventType,
		Connection: conn,
	}:
	default:
	}
}
