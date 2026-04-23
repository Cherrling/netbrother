package capture

import (
	"context"
	"fmt"
)

// Capturer is the abstraction over packet capture sources.
// Implementations: pcapCapturer, procCapturer.
type Capturer interface {
	// Start begins capturing and returns a channel of events.
	// The implementation MUST close the channel when ctx is cancelled.
	Start(ctx context.Context) (<-chan Event, error)

	// Close releases all resources held by the capturer.
	Close() error

	// Name returns the backend name: "pcap" or "proc".
	Name() string

	// RequiresRoot returns true if the backend needs elevated privileges.
	RequiresRoot() bool
}

// pcapDetect is set by capture_pcap.go init(); nil when built with nopcap tag.
var pcapDetect func() bool

// procDetect is set by capture_proc.go init().
var procDetect func() bool

// AvailableBackends returns a list of backends that work on this system.
// Ordered by preference: pcap first, proc second.
func AvailableBackends() []string {
	var backends []string
	if pcapDetect != nil && pcapDetect() {
		backends = append(backends, "pcap")
	}
	if procDetect != nil && procDetect() {
		backends = append(backends, "proc")
	}
	return backends
}

// newPcap is set by capture_pcap.go when compiled with pcap support.
var newPcap func(iface string) (Capturer, error)

// New creates the best available Capturer for the given interface.
// Falls back gracefully: pcap -> proc -> error.
func New(iface string) (Capturer, error) {
	// Try pcap first (if available)
	if newPcap != nil && pcapDetect != nil && pcapDetect() {
		c, err := newPcap(iface)
		if err == nil {
			return c, nil
		}
	}

	// Fall back to /proc
	if procDetect != nil && procDetect() {
		c, err := newProcCapturer()
		if err == nil {
			return c, nil
		}
	}

	return nil, fmt.Errorf("no capture backend available")
}
