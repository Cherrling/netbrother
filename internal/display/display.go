package display

import (
	"context"
	"fmt"

	"github.com/netbrother/netbrother/internal/capture"
)

// Displayer is the abstraction over output modes.
type Displayer interface {
	Start(ctx context.Context, events <-chan capture.Event) error
	Close() error
}

// LogConfig configures the log-mode display.
type LogConfig struct {
	JSON  bool
	Color bool
}

// Config configures display features shared across modes.
type Config struct {
	Keep         bool   // keep closed connections visible
	Output       string // file path to save all connections
	ShowTimeWait bool   // show TIME_WAIT connections
}

// New creates a Displayer based on the requested mode.
func New(mode string, displayCfg Config, logCfg LogConfig) (Displayer, error) {
	switch mode {
	case "tui":
		return newTUDisplay(displayCfg)
	case "log":
		return newLogDisplayer(logCfg), nil
	default:
		return nil, fmt.Errorf("unknown display mode: %q", mode)
	}
}
