package display

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/netbrother/netbrother/internal/capture"
	"github.com/netbrother/netbrother/internal/types"
)

// ANSI escape codes for terminal control.
const (
	ansiClearScreen = "\033[2J"
	ansiHome        = "\033[H"
	ansiHideCursor  = "\033[?25l"
	ansiShowCursor  = "\033[?25h"
	ansiBold        = "\033[1m"
	ansiReset       = "\033[0m"

	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiWhite  = "\033[37m"

	ansiRedBg    = "\033[41m"
	ansiYellowBg = "\033[43m"
	ansiBlueBg   = "\033[44m"
)

type tuiDisplayer struct {
	mu           sync.Mutex
	connections  []types.Connection
	alerts       []capture.Alert
	filter       string
	showAlerts   bool
	maxAlerts    int
	maxConns     int
	running      bool
	done         chan struct{}
	captureMode  string
}

func newTUDisplay() (*tuiDisplayer, error) {
	return &tuiDisplayer{
		maxAlerts:  100,
		maxConns:   500,
		done:       make(chan struct{}),
	}, nil
}

func (t *tuiDisplayer) Close() error {
	if t.running {
		close(t.done)
	}
	fmt.Fprint(os.Stderr, ansiShowCursor)
	return nil
}

func (t *tuiDisplayer) Start(ctx context.Context, events <-chan capture.Event) error {
	t.running = true
	defer func() { t.running = false }()

	// Handle terminal signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	// Keyboard input in a separate goroutine
	inputCh := make(chan rune, 10)
	go t.readInput(inputCh)

	// Hide cursor
	fmt.Fprint(os.Stderr, ansiHideCursor)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Initial render
	t.render()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprint(os.Stderr, ansiShowCursor)
			return ctx.Err()
		case <-t.done:
			fmt.Fprint(os.Stderr, ansiShowCursor)
			return nil
		case <-sigCh:
			// Terminal resized, re-render
			t.render()
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			t.handleEvent(evt)
		case <-ticker.C:
			t.render()
		case r := <-inputCh:
			switch {
			case r == 'q' || r == 'Q':
				fmt.Fprint(os.Stderr, ansiShowCursor)
				return nil
			case r == 'a' || r == 'A':
				t.mu.Lock()
				t.showAlerts = !t.showAlerts
				t.mu.Unlock()
				t.render()
			case r == '/':
				t.mu.Lock()
				t.filter = ""
				t.mu.Unlock()
				t.promptFilter()
			}
		}
	}
}

func (t *tuiDisplayer) readInput(ch chan<- rune) {
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		// Only pass printable characters and control chars we care about
		r := rune(buf[0])
		if r == 'q' || r == 'Q' || r == 'a' || r == 'A' || r == '/' || r == '\n' || r == '\b' || r == 0x7f {
			select {
			case ch <- r:
			default:
			}
		}
	}
}

func (t *tuiDisplayer) promptFilter() {
	// Show filter prompt at bottom
	fmt.Fprintf(os.Stderr, "\033[%d;1H", t.terminalHeight()) // last line
	fmt.Fprintf(os.Stderr, "\033[K")                          // clear line
	fmt.Fprintf(os.Stderr, "Filter: ")

	// Read filter input (simple line-based)
	var filter strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		r := rune(buf[0])
		if r == '\n' || r == '\r' {
			break
		}
		if (r == '\b' || r == 0x7f) && filter.Len() > 0 {
			s := filter.String()
			filter.Reset()
			filter.WriteString(s[:len(s)-1])
		} else if unicode.IsPrint(r) {
			filter.WriteRune(r)
		}
		fmt.Fprintf(os.Stderr, "\033[%d;1H", t.terminalHeight())
		fmt.Fprintf(os.Stderr, "\033[K")
		fmt.Fprintf(os.Stderr, "Filter: %s", filter.String())
	}

	t.mu.Lock()
	t.filter = filter.String()
	t.mu.Unlock()
	t.render()
}

func (t *tuiDisplayer) handleEvent(evt capture.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch evt.Type {
	case capture.EventNewConnection:
		t.connections = append(t.connections, evt.Connection)
		if len(t.connections) > t.maxConns {
			t.connections = t.connections[len(t.connections)-t.maxConns:]
		}
	case capture.EventConnectionClosed:
		// Remove from active connections
		key := evt.Connection.Key()
		for i, c := range t.connections {
			if c.Key() == key {
				t.connections = append(t.connections[:i], t.connections[i+1:]...)
				break
			}
		}
	}

	// Add alerts
	for _, a := range evt.Alerts {
		t.alerts = append(t.alerts, a)
		if len(t.alerts) > t.maxAlerts {
			t.alerts = t.alerts[len(t.alerts)-t.maxAlerts:]
		}
	}
}

func (t *tuiDisplayer) render() {
	t.mu.Lock()
	defer t.mu.Unlock()

	width := t.terminalWidth()
	height := t.terminalHeight()

	out := &strings.Builder{}

	// Clear screen and move home
	out.WriteString(ansiClearScreen)
	out.WriteString(ansiHome)

	// Header bar
	t.renderHeader(out, width)

	// Connection table
	tableHeight := height - 5
	if t.showAlerts {
		tableHeight = height / 2
	}
	t.renderTable(out, width, tableHeight)

	// Alerts section
	if t.showAlerts {
		t.renderAlerts(out, width, height-tableHeight-2)
	}

	// Status bar
	t.renderStatusBar(out, width)

	fmt.Fprint(os.Stderr, out.String())
}

func (t *tuiDisplayer) renderHeader(out *strings.Builder, width int) {
	title := fmt.Sprintf(" netbrother | mode: proc | conns: %d | alerts: %d ",
		len(t.connections), len(t.alerts))

	// Pad with spaces to fill width
	if len(title) < width {
		title += strings.Repeat(" ", width-len(title))
	} else if len(title) > width {
		title = title[:width]
	}

	out.WriteString(ansiBold)
	out.WriteString(ansiWhite)
	out.WriteString(ansiBlueBg)
	out.WriteString(title)
	out.WriteString(ansiReset)
	out.WriteString("\n")
}

func (t *tuiDisplayer) renderTable(out *strings.Builder, width int, maxRows int) {
	// Column headers
	header := fmt.Sprintf(" %-5s %-10s %-21s %-21s %-7s %s",
		"PID", "PROC", "LOCAL", "REMOTE", "STATE", "ALERT")
	if len(header) > width {
		header = header[:width]
	}
	out.WriteString(ansiBold)
	out.WriteString(header)
	out.WriteString(ansiReset)
	out.WriteString("\n")

	// Divider
	divider := strings.Repeat("-", width)
	out.WriteString(divider)
	out.WriteString("\n")

	// Filter connections
	conns := t.filteredConnections()
	if len(conns) > maxRows {
		conns = conns[:maxRows]
	}

	for _, c := range conns {
		hasAlert := t.hasAlertForConn(c)
		pidStr := fmt.Sprintf("%d", c.PID)
		if c.PID == 0 {
			pidStr = "?"
		}
		procName := c.ProcessName
		if procName == "" {
			procName = "?"
		}
		localAddr := fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort)
		remoteAddr := fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort)

		alertMarker := ""
		if hasAlert {
			alertMarker = ansiRed + " ***" + ansiReset
		}

		stateStr := c.State.String()

		line := fmt.Sprintf(" %5s %-10s %-21s %-21s %-7s %s",
			pidStr, procName, localAddr, remoteAddr, stateStr, alertMarker)

		if len(line) > width {
			line = line[:width]
		}

		// Color suspicious connections
		if hasAlert {
			out.WriteString(ansiYellowBg)
			out.WriteString(line)
			out.WriteString(ansiReset)
		} else {
			out.WriteString(line)
		}
		out.WriteString("\n")
	}
}

func (t *tuiDisplayer) renderAlerts(out *strings.Builder, width int, maxRows int) {
	out.WriteString("\n")
	header := " ALERTS:"
	out.WriteString(ansiBold)
	out.WriteString(header)
	out.WriteString(ansiReset)
	out.WriteString("\n")

	divider := strings.Repeat("-", width)
	out.WriteString(divider)
	out.WriteString("\n")

	alerts := t.alerts
	if len(alerts) > maxRows {
		alerts = alerts[len(alerts)-maxRows:]
	}

	for _, a := range alerts {
		severityColor := ansiYellow
		if a.Severity == capture.SeverityHigh {
			severityColor = ansiRed
		} else if a.Severity == capture.SeverityLow {
			severityColor = ansiGreen
		}

		line := fmt.Sprintf(" [%s%s%s] %s",
			severityColor, a.Severity.String(), ansiReset, a.Message)
		if len(line) > width {
			line = line[:width]
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
}

func (t *tuiDisplayer) renderStatusBar(out *strings.Builder, width int) {
	out.WriteString("\n")
	hint := "[q] quit  [/] filter  [a] toggle alerts"
	if len(hint) > width {
		hint = hint[:width]
	} else {
		hint += strings.Repeat(" ", width-len(hint))
	}
	out.WriteString(ansiCyan)
	out.WriteString(hint)
	out.WriteString(ansiReset)
}

func (t *tuiDisplayer) filteredConnections() []types.Connection {
	if t.filter == "" {
		// Sort by PID for display
		sorted := make([]types.Connection, len(t.connections))
		copy(sorted, t.connections)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].PID < sorted[j].PID
		})
		return sorted
	}

	filterLower := strings.ToLower(t.filter)
	var filtered []types.Connection
	for _, c := range t.connections {
		if strings.Contains(strings.ToLower(c.ProcessName), filterLower) ||
			strings.Contains(c.RemoteIP.String(), filterLower) ||
			strings.Contains(fmt.Sprintf("%d", c.RemotePort), filterLower) ||
			strings.Contains(fmt.Sprintf("%d", c.PID), filterLower) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func (t *tuiDisplayer) hasAlertForConn(c types.Connection) bool {
	key := c.Key()
	for _, a := range t.alerts {
		if a.Connection.Key() == key {
			return true
		}
	}
	return false
}

func (t *tuiDisplayer) terminalWidth() int {
	return 80
}

func (t *tuiDisplayer) terminalHeight() int {
	return 24
}
