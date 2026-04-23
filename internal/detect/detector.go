package detect

import (
	"github.com/netbrother/netbrother/internal/capture"
)

// Detector is the interface for connection analysis engines.
type Detector interface {
	// Analyze examines an event and returns any alerts generated.
	Analyze(evt capture.Event) []capture.Alert

	// Reset clears all detector state.
	Reset()
}

// Orchestrator runs multiple detectors and aggregates alerts.
type Orchestrator struct {
	detectors []Detector
}

// Config configures the detection engine.
type Config struct {
	BadPorts    []PortRange
	BadIPs      []string
	Window      int     // sliding window in seconds (default: 300 = 5m)
	MinSamples  int     // minimum connections before analysis (default: 3)
	CVThreshold float64 // max coefficient of variation (default: 0.25)
}

// PortRange defines a range of suspicious ports.
type PortRange struct {
	Start uint16
	End   uint16
}

// DefaultBadPorts returns the default set of suspicious port ranges.
func DefaultBadPorts() []PortRange {
	return []PortRange{
		{4444, 4444},   // Metasploit default, common reverse shell
		{1337, 1337},   // generic "leet" port
		{31337, 31337}, // generic "elite" port
		{6660, 6669},   // IRC, often used for C2
		{5555, 5555},   // common CTF backdoor
		{7777, 7777},
		{8888, 8888},
		{9999, 9999},
	}
}

// DefaultConfig returns the default detection configuration.
func DefaultConfig() Config {
	return Config{
		BadPorts:    DefaultBadPorts(),
		Window:      300,
		MinSamples:  3,
		CVThreshold: 0.25,
	}
}

// NewOrchestrator creates an orchestrator with all detectors.
func NewOrchestrator(cfg Config) *Orchestrator {
	return &Orchestrator{
		detectors: []Detector{
			newPeriodicDetector(cfg),
			newNoveltyDetector(),
			newSuspiciousDetector(cfg),
		},
	}
}

// Analyze runs all detectors against an event and returns aggregated alerts.
func (o *Orchestrator) Analyze(evt capture.Event) []capture.Alert {
	// Only analyze new connections (don't alert on close events)
	if evt.Type != capture.EventNewConnection {
		return nil
	}

	var alerts []capture.Alert
	for _, d := range o.detectors {
		alerts = append(alerts, d.Analyze(evt)...)
	}
	return alerts
}

// Reset clears all detector state.
func (o *Orchestrator) Reset() {
	for _, d := range o.detectors {
		d.Reset()
	}
}
