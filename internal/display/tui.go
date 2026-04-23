package display

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	rawTerminal  bool

	// filter state — accessed only from the main goroutine
	filterMode bool
	filterBuf  strings.Builder
}

func newTUDisplay() (*tuiDisplayer, error) {
	return &tuiDisplayer{
		maxAlerts: 100,
		maxConns:  500,
		done:      make(chan struct{}),
	}, nil
}

func (t *tuiDisplayer) Close() error {
	if t.running {
		close(t.done)
	}
	fmt.Fprint(os.Stderr, ansiShowCursor)
	t.restoreTerminal()
	return nil
}

func (t *tuiDisplayer) setRawMode() error {
	cmd := exec.Command("stty", "-icanon", "-echo", "min", "1", "time", "0")
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return err
	}
	t.rawTerminal = true
	return nil
}

func (t *tuiDisplayer) restoreTerminal() {
	if t.rawTerminal {
		exec.Command("stty", "sane").Run()
		t.rawTerminal = false
	}
}

func (t *tuiDisplayer) Start(ctx context.Context, events <-chan capture.Event) error {
	t.running = true
	defer func() { t.running = false }()

	if err := t.setRawMode(); err != nil {
		return fmt.Errorf("raw terminal: %w", err)
	}
	defer t.restoreTerminal()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	// Single input goroutine — sends EVERY byte as a uint32 rune.
	inputCh := make(chan rune, 64)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(inputCh)
				return
			}
			inputCh <- rune(buf[0])
		}
	}()

	fmt.Fprint(os.Stderr, ansiHideCursor)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	t.render()

	for {
		// If we are in filter mode, only process input — don't select other
		// channels so that keystrokes aren't stolen by other cases.
		if t.filterMode {
			if !t.handleFilterInput(inputCh) {
				return nil
			}
			continue
		}

		select {
		case <-ctx.Done():
			fmt.Fprint(os.Stderr, ansiShowCursor)
			return ctx.Err()
		case <-t.done:
			fmt.Fprint(os.Stderr, ansiShowCursor)
			return nil
		case <-sigCh:
			t.render()
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			t.handleEvent(evt)
		case <-ticker.C:
			t.render()
		case r, ok := <-inputCh:
			if !ok {
				return nil
			}
			t.handleCommand(r)
		}
	}
}

// handleFilterInput processes one filter-mode keystroke.
// Returns false if the program should exit.
func (t *tuiDisplayer) handleFilterInput(inputCh chan rune) bool {
	select {
	case r, ok := <-inputCh:
		if !ok {
			return false
		}
		switch {
		case r == '\n' || r == '\r':
			t.filter = t.filterBuf.String()
			t.filterBuf.Reset()
			t.filterMode = false
			t.render()
		case (r == '\b' || r == 0x7f) && t.filterBuf.Len() > 0:
			s := t.filterBuf.String()
			t.filterBuf.Reset()
			t.filterBuf.WriteString(s[:len(s)-1])
			t.showFilterPrompt()
		case unicode.IsPrint(r):
			t.filterBuf.WriteRune(r)
			t.showFilterPrompt()
		case r == 'q' || r == 'Q':
			return false
		}
	default:
		// no input available — briefly yield so the select in Start() can
		// pick up events, ticks, etc.
		// We use a tiny sleep to avoid busy looping.
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

func (t *tuiDisplayer) showFilterPrompt() {
	fmt.Fprintf(os.Stderr, "\033[%d;1H", t.terminalHeight())
	fmt.Fprintf(os.Stderr, "\033[K")
	fmt.Fprintf(os.Stderr, "Filter: %s", t.filterBuf.String())
}

func (t *tuiDisplayer) handleCommand(r rune) {
	switch {
	case r == 'q' || r == 'Q':
		fmt.Fprint(os.Stderr, ansiShowCursor)
		t.running = false
		close(t.done)
	case r == 'a' || r == 'A':
		t.mu.Lock()
		t.showAlerts = !t.showAlerts
		t.mu.Unlock()
		t.render()
	case r == '/':
		t.mu.Lock()
		t.filter = ""
		t.mu.Unlock()
		t.filterBuf.Reset()
		t.filterMode = true
		t.showFilterPrompt()
	}
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
		key := evt.Connection.Key()
		for i, c := range t.connections {
			if c.Key() == key {
				t.connections = append(t.connections[:i], t.connections[i+1:]...)
				break
			}
		}
	}

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
	out.WriteString(ansiClearScreen)
	out.WriteString(ansiHome)

	t.renderHeader(out, width)

	tableHeight := height - 5
	if t.showAlerts {
		tableHeight = height / 2
	}
	t.renderTable(out, width, tableHeight)

	if t.showAlerts {
		t.renderAlerts(out, width, height-tableHeight-2)
	}

	t.renderStatusBar(out, width)

	fmt.Fprint(os.Stderr, out.String())
}

func (t *tuiDisplayer) renderHeader(out *strings.Builder, width int) {
	title := fmt.Sprintf(" netbrother | mode: proc | conns: %d | alerts: %d ",
		len(t.connections), len(t.alerts))
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
	header := fmt.Sprintf(" %-5s %-10s %-21s %-21s %-7s %s",
		"PID", "PROC", "LOCAL", "REMOTE", "STATE", "ALERT")
	if len(header) > width {
		header = header[:width]
	}
	out.WriteString(ansiBold)
	out.WriteString(header)
	out.WriteString(ansiReset)
	out.WriteString("\n")

	out.WriteString(strings.Repeat("-", width))
	out.WriteString("\n")

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

		line := fmt.Sprintf(" %5s %-10s %-21s %-21s %-7s %s",
			pidStr, procName, localAddr, remoteAddr, c.State.String(), alertMarker)

		if len(line) > width {
			line = line[:width]
		}

		if hasAlert {
			out.WriteString(ansiYellow)
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
	out.WriteString(ansiBold)
	out.WriteString(" ALERTS:")
	out.WriteString(ansiReset)
	out.WriteString("\n")

	out.WriteString(strings.Repeat("-", width))
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
