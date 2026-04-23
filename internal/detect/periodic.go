package detect

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/netbrother/netbrother/internal/capture"
)

type beaconKey struct {
	PID        int
	RemoteIP   string
	RemotePort uint16
}

type periodicDetector struct {
	mu         sync.Mutex
	history    map[beaconKey][]time.Time
	alerted    map[beaconKey]time.Time // when last alerted (for cooldown)
	window     time.Duration
	minSamples int
	maxCV      float64
	cooldown   time.Duration
}

func newPeriodicDetector(cfg Config) *periodicDetector {
	cd := time.Duration(cfg.Window) * time.Second
	if cd <= 0 {
		cd = 300 * time.Second
	}
	minSamp := cfg.MinSamples
	if minSamp <= 0 {
		minSamp = 3
	}
	cv := cfg.CVThreshold
	if cv <= 0 {
		cv = 0.25
	}

	return &periodicDetector{
		history:    make(map[beaconKey][]time.Time),
		alerted:    make(map[beaconKey]time.Time),
		window:     cd,
		minSamples: minSamp,
		maxCV:      cv,
		cooldown:   60 * time.Second,
	}
}

func (d *periodicDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.history = make(map[beaconKey][]time.Time)
	d.alerted = make(map[beaconKey]time.Time)
}

func (d *periodicDetector) Analyze(evt capture.Event) []capture.Alert {
	if evt.Type != capture.EventNewConnection {
		return nil
	}

	conn := evt.Connection
	key := beaconKey{
		PID:        conn.PID,
		RemoteIP:   conn.RemoteIP.String(),
		RemotePort: conn.RemotePort,
	}

	now := evt.Timestamp

	d.mu.Lock()
	defer d.mu.Unlock()

	// Append and prune
	d.history[key] = append(d.history[key], now)
	d.prune(key, now)

	if len(d.history[key]) < d.minSamples {
		return nil
	}

	// Check cooldown
	if lastAlert, ok := d.alerted[key]; ok {
		if now.Sub(lastAlert) < d.cooldown {
			return nil
		}
	}

	// Compute intervals between consecutive timestamps
	timestamps := d.history[key]
	deltas := make([]float64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		delta := timestamps[i].Sub(timestamps[i-1]).Seconds()
		if delta > 0 {
			deltas = append(deltas, delta)
		}
	}

	if len(deltas) < 2 {
		return nil
	}

	mean, stddev := meanStdDev(deltas)
	if mean <= 0 {
		return nil
	}

	cv := stddev / mean
	if cv > d.maxCV {
		return nil
	}

	// It's periodic!
	d.alerted[key] = now

	procName := conn.ProcessName
	if procName == "" {
		procName = "?"
	}

	msg := fmt.Sprintf("PID %d (%s) -> %s:%d every ~%.0fs (CV=%.2f)",
		conn.PID, procName, conn.RemoteIP, conn.RemotePort, mean, cv)

	return []capture.Alert{{
		Type:       capture.AlertPeriodicConnection,
		Severity:   capture.SeverityHigh,
		Message:    msg,
		Connection: conn,
		Timestamp:  now,
	}}
}

func (d *periodicDetector) prune(key beaconKey, reference time.Time) {
	cutoff := reference.Add(-d.window)
	ts := d.history[key]
	keep := 0
	for _, t := range ts {
		if t.After(cutoff) {
			ts[keep] = t
			keep++
		}
	}
	d.history[key] = ts[:keep]
}

func meanStdDev(values []float64) (mean, stddev float64) {
	if len(values) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))

	var varianceSum float64
	for _, v := range values {
		d := v - mean
		varianceSum += d * d
	}
	stddev = math.Sqrt(varianceSum / float64(len(values)))
	return mean, stddev
}
