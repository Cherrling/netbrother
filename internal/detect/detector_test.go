package detect

import (
	"net"
	"testing"
	"time"

	"github.com/netbrother/netbrother/internal/capture"
	"github.com/netbrother/netbrother/internal/types"
)

func makeConn(remoteIP string, remotePort uint16, pid int, procName string) types.Connection {
	return types.Connection{
		LocalIP:     net.ParseIP("10.0.0.2"),
		LocalPort:   43001,
		RemoteIP:    net.ParseIP(remoteIP),
		RemotePort:  remotePort,
		PID:         pid,
		ProcessName: procName,
		State:       types.StateEstablished,
		Direction:   types.DirectionOutbound,
		CreatedAt:   time.Now(),
	}
}

func makeEvent(conn types.Connection) capture.Event {
	return capture.Event{
		Timestamp:  time.Now(),
		Type:       capture.EventNewConnection,
		Connection: conn,
	}
}

func TestPeriodicDetector_NotEnoughSamples(t *testing.T) {
	d := newPeriodicDetector(DefaultConfig())
	conn := makeConn("10.0.0.5", 4444, 1234, "nc")

	// One connection shouldn't trigger
	alerts := d.Analyze(makeEvent(conn))
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts with 1 sample, got %d", len(alerts))
	}
}

func TestPeriodicDetector_RegularInterval(t *testing.T) {
	d := newPeriodicDetector(DefaultConfig())
	conn := makeConn("10.0.0.5", 4444, 1234, "nc")

	// Simulate 5 connections at exactly 70s intervals (exceeds cooldown)
	base := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	alertCount := 0
	for i := 0; i < 5; i++ {
		evt := capture.Event{
			Timestamp:  base.Add(time.Duration(i) * 70 * time.Second),
			Type:       capture.EventNewConnection,
			Connection: conn,
		}
		alerts := d.Analyze(evt)
		if len(alerts) > 0 {
			alertCount++
			if alerts[0].Type != capture.AlertPeriodicConnection {
				t.Errorf("expected AlertPeriodicConnection, got %v", alerts[0].Type)
			}
		}
	}
	// Should have detected periodicity at least once
	if alertCount == 0 {
		t.Fatal("expected at least one periodic alert")
	}
}

func TestPeriodicDetector_IrregularInterval(t *testing.T) {
	d := newPeriodicDetector(Config{
		MinSamples:  4,
		CVThreshold: 0.25,
		Window:      300,
	})
	conn := makeConn("10.0.0.5", 4444, 1234, "nc")

	// Simulate 4 connections with very irregular intervals (1s, 10s, 1s)
	base := time.Now()
	intervals := []time.Duration{0, time.Second, 10 * time.Second, time.Second}
	for i, interval := range intervals {
		evt := capture.Event{
			Timestamp:  base.Add(interval),
			Type:       capture.EventNewConnection,
			Connection: conn,
		}
		if i == 0 {
			evt.Timestamp = base
		}
		alerts := d.Analyze(evt)
		if i >= 3 && len(alerts) > 0 {
			t.Fatalf("expected no alert for irregular pattern, got %d", len(alerts))
		}
	}
}

func TestNoveltyDetector_NewProcess(t *testing.T) {
	d := newNoveltyDetector()
	conn := makeConn("10.0.0.5", 4444, 1234, "nc")

	alerts := d.Analyze(makeEvent(conn))
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts (new process + new connection), got %d", len(alerts))
	}
	if alerts[0].Type != capture.AlertNewProcess {
		t.Errorf("expected first alert to be NewProcess, got %v", alerts[0].Type)
	}

	// Second connection from same process, different local port -> new conn, but not new proc
	conn2 := makeConn("10.0.0.5", 4444, 1234, "nc")
	conn2.LocalPort = 43002
	alerts2 := d.Analyze(makeEvent(conn2))
	if len(alerts2) != 1 {
		t.Fatalf("expected 1 alert (new connection only), got %d", len(alerts2))
	}
	if alerts2[0].Type != capture.AlertNewConnection {
		t.Errorf("expected alert to be NewConnection, got %v", alerts2[0].Type)
	}
}

func TestSuspiciousDetector_BadPort(t *testing.T) {
	d := newSuspiciousDetector(DefaultConfig())
	conn := makeConn("10.0.0.5", 4444, 1234, "nc")

	alerts := d.Analyze(makeEvent(conn))
	if len(alerts) == 0 {
		t.Fatal("expected alert for port 4444")
	}
	if alerts[0].Type != capture.AlertSuspiciousPort {
		t.Errorf("expected SuspiciousPort alert, got %v", alerts[0].Type)
	}
}

func TestSuspiciousDetector_NormalPort(t *testing.T) {
	d := newSuspiciousDetector(DefaultConfig())
	conn := makeConn("93.184.216.34", 80, 5678, "curl")

	alerts := d.Analyze(makeEvent(conn))
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts for port 80, got %d", len(alerts))
	}
}

func TestMeanStdDev(t *testing.T) {
	values := []float64{10, 10, 10, 10}
	mean, stddev := meanStdDev(values)
	if mean != 10 {
		t.Errorf("mean = %f, want 10", mean)
	}
	if stddev != 0 {
		t.Errorf("stddev = %f, want 0", stddev)
	}

	values2 := []float64{1, 2, 3, 4, 5}
	mean2, stddev2 := meanStdDev(values2)
	if mean2 != 3 {
		t.Errorf("mean = %f, want 3", mean2)
	}
	// stddev should be sqrt(2) ≈ 1.414
	if stddev2 < 1.4 || stddev2 > 1.42 {
		t.Errorf("stddev = %f, want ~1.414", stddev2)
	}
}
