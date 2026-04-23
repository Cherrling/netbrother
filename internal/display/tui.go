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
	"unsafe"

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

	ansiBlueBg = "\033[44m"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

type tuiDisplayer struct {
	mu          sync.Mutex
	connections []types.Connection
	alerts      []capture.Alert
	filter      string
	showAlerts  bool
	maxAlerts   int
	maxConns    int
	running     bool
	done        chan struct{}
	rawTerminal bool

	// filter state
	filterMode bool
	filterBuf  strings.Builder

	// terminal dimensions (updated on SIGWINCH)
	termWidth  int
	termHeight int

	// scroll offset
	scroll int

	// options
	keep         bool // keep closed connections visible
	showTimeWait bool // show TIME_WAIT connections
}

func newTUDisplay(cfg Config) (*tuiDisplayer, error) {
	w, h := getTermSize()
	return &tuiDisplayer{
		maxAlerts:    100,
		maxConns:     500,
		done:         make(chan struct{}),
		termWidth:    w,
		termHeight:   h,
		keep:         cfg.Keep,
		showTimeWait: cfg.ShowTimeWait,
	}, nil
}

func getTermSize() (width, height int) {
	ws := &winsize{}
	ret, _, _ := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), 0x5413 /* TIOCGWINSZ */, uintptr(unsafe.Pointer(ws)))
	if ret == 0 && ws.Col > 0 && ws.Row > 0 {
		return int(ws.Col), int(ws.Row)
	}
	return 80, 24
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
			t.termWidth, t.termHeight = getTermSize()
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
			t.scroll = 0
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
		case r == 0x1b: // ESC — cancel filter
			t.filterBuf.Reset()
			t.filterMode = false
			t.render()
		}
	default:
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

func (t *tuiDisplayer) showFilterPrompt() {
	fmt.Fprintf(os.Stderr, "\033[%d;1H", t.termHeight)
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
	case r == 'j' || r == 'J':
		t.scroll++
		t.render()
	case r == 'k' || r == 'K':
		if t.scroll > 0 {
			t.scroll--
		}
		t.render()
	case r == 'g':
		t.scroll = 0
		t.render()
	case r == 'G':
		t.scroll = t.maxScroll()
		t.render()
	case r == 't' || r == 'T':
		t.mu.Lock()
		t.showTimeWait = !t.showTimeWait
		t.mu.Unlock()
		t.render()
	}
}

func (t *tuiDisplayer) handleEvent(evt capture.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch evt.Type {
	case capture.EventNewConnection:
		if !t.showTimeWait && evt.Connection.State == types.StateTimeWait {
			return
		}
		t.connections = append(t.connections, evt.Connection)
		if len(t.connections) > t.maxConns {
			t.connections = t.connections[len(t.connections)-t.maxConns:]
		}
	case capture.EventConnectionClosed:
		if t.keep {
			key := evt.Connection.Key()
			for i, c := range t.connections {
				if c.Key() == key {
					t.connections[i].State = types.StateClose
					break
				}
			}
		} else {
			key := evt.Connection.Key()
			for i, c := range t.connections {
				if c.Key() == key {
					t.connections = append(t.connections[:i], t.connections[i+1:]...)
					break
				}
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

func (t *tuiDisplayer) maxScroll() int {
	t.mu.Lock()
	total := len(t.filteredConnections())
	t.mu.Unlock()
	rows := t.visibleRows()
	if total <= rows {
		return 0
	}
	return total - rows
}

func (t *tuiDisplayer) visibleRows() int {
	rows := t.termHeight - 4 // header(1) + header line(1) + divider(1) + status(1)
	if t.showAlerts {
		rows = t.termHeight/2 - 4
	}
	if rows < 1 {
		rows = 1
	}
	return rows
}

func (t *tuiDisplayer) render() {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := &strings.Builder{}
	out.WriteString(ansiClearScreen)
	out.WriteString(ansiHome)

	t.renderHeader(out)

	rows := t.visibleRows()
	t.renderTable(out, rows)

	if t.showAlerts {
		alertRows := t.termHeight/2 - 2
		t.renderAlerts(out, alertRows)
	}

	t.renderStatusBar(out)

	fmt.Fprint(os.Stderr, out.String())
}

func (t *tuiDisplayer) renderHeader(out *strings.Builder) {
	total := len(t.connections)
	filtered := len(t.filteredConnections())
	title := fmt.Sprintf(" netbrother | conns: %d", total)
	if t.filter != "" {
		title += fmt.Sprintf(" (filtered: %d)", filtered)
	}
	if !t.showTimeWait {
		title += " (hide TIME_WAIT)"
	}
	title += fmt.Sprintf(" | alerts: %d ", len(t.alerts))

	if len(title) < t.termWidth {
		title += strings.Repeat(" ", t.termWidth-len(title))
	} else if len(title) > t.termWidth {
		title = title[:t.termWidth]
	}
	out.WriteString(ansiBold)
	out.WriteString(ansiWhite)
	out.WriteString(ansiBlueBg)
	out.WriteString(title)
	out.WriteString(ansiReset)
	out.WriteString("\n")
}

func (t *tuiDisplayer) renderTable(out *strings.Builder, maxRows int) {
	header := fmt.Sprintf(" %-5s %-12s %-21s %-21s %-8s",
		"PID", "PROC", "LOCAL", "REMOTE", "STATE")
	out.WriteString(ansiBold)
	out.WriteString(header)
	out.WriteString(ansiReset)
	out.WriteString("\n")

	out.WriteString(strings.Repeat("-", t.termWidth))
	out.WriteString("\n")

	conns := t.filteredConnections()

	// Clamp scroll to valid range
	maxScroll := 0
	if len(conns) > maxRows {
		maxScroll = len(conns) - maxRows
	}
	if t.scroll > maxScroll {
		t.scroll = maxScroll
	}

	start := t.scroll
	end := start + maxRows
	if end > len(conns) {
		end = len(conns)
	}

	for _, c := range conns[start:end] {
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
		stateStr := c.State.String()

		alertMarker := ""
		if hasAlert {
			alertMarker = ansiRed + " ***" + ansiReset
		}

		line := fmt.Sprintf(" %5s %-12s %-21s %-21s %-8s%s",
			pidStr, procName, localAddr, remoteAddr, stateStr, alertMarker)

		if len(line) > t.termWidth {
			line = line[:t.termWidth]
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

	// Show scroll indicator
	if len(conns) > maxRows {
		pct := 0
		if len(conns) > 0 {
			pct = (t.scroll + maxRows) * 100 / len(conns)
			if pct > 100 {
				pct = 100
			}
		}
		indicator := fmt.Sprintf(" %d/%d connections (%d%%)  [j] down  [k] up  [g] top  [G] bottom",
			end, len(conns), pct)
		if len(indicator) > t.termWidth {
			indicator = indicator[:t.termWidth]
		}
		out.WriteString(ansiCyan)
		out.WriteString(indicator)
		out.WriteString(ansiReset)
		out.WriteString("\n")
	}
}

func (t *tuiDisplayer) renderAlerts(out *strings.Builder, maxRows int) {
	out.WriteString("\n")
	out.WriteString(ansiBold)
	out.WriteString(" ALERTS:")
	out.WriteString(ansiReset)
	out.WriteString("\n")

	out.WriteString(strings.Repeat("-", t.termWidth))
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
		if len(line) > t.termWidth {
			line = line[:t.termWidth]
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
}

func (t *tuiDisplayer) renderStatusBar(out *strings.Builder) {
	conns := t.filteredConnections()
	hint := "[q] quit  [/] filter  [j/k] scroll  [a] alerts"
	if len(conns) > t.visibleRows() {
		hint = "[q] quit  [/] filter  [j/k] scroll  [g/G] top/bottom  [a] alerts"
	}
	hint += "  [t] timewait"
	if len(hint) > t.termWidth {
		hint = hint[:t.termWidth]
	} else {
		hint += strings.Repeat(" ", t.termWidth-len(hint))
	}
	out.WriteString(ansiCyan)
	out.WriteString(hint)
	out.WriteString(ansiReset)
}

func (t *tuiDisplayer) filteredConnections() []types.Connection {
	var base []types.Connection
	if !t.showTimeWait {
		for _, c := range t.connections {
			if c.State != types.StateTimeWait {
				base = append(base, c)
			}
		}
	} else {
		base = t.connections
	}

	if t.filter == "" {
		sorted := make([]types.Connection, len(base))
		copy(sorted, base)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].PID < sorted[j].PID
		})
		return sorted
	}

	filterLower := strings.ToLower(t.filter)
	var filtered []types.Connection
	for _, c := range base {
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
