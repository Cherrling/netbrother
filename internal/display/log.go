package display

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/netbrother/netbrother/internal/capture"
	"github.com/netbrother/netbrother/internal/process"
)

type logDisplayer struct {
	writer   io.Writer
	mu       sync.Mutex
	headerLn bool
}

func newLogDisplayer(cfg LogConfig) *logDisplayer {
	return &logDisplayer{
		writer: os.Stdout,
	}
}

func (l *logDisplayer) Close() error {
	return nil
}

func (l *logDisplayer) Start(ctx context.Context, events <-chan capture.Event) error {
	l.printHeader()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			l.renderEvent(evt)
		}
	}
}

func (l *logDisplayer) printHeader() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.writer, "%-22s  %-22s  %-8s  %-20s  %s\n",
		"LOCAL", "REMOTE", "PID", "PROC", "EXE")
	fmt.Fprintln(l.writer, "----------------------  ----------------------  --------  --------------------  --------")
	l.headerLn = true
}

func (l *logDisplayer) renderEvent(evt capture.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	conn := evt.Connection
	exePath, _ := process.ProcessExePath(conn.PID)
	local := fmt.Sprintf("%s:%d", conn.LocalIP, conn.LocalPort)
	remote := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)
	fmt.Fprintf(l.writer, "%-22s  %-22s  %-8d  %-20s  %s\n",
		local, remote,
		conn.PID, conn.ProcessName, exePath)
}
