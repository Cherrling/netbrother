package display

import (
	"context"
	"fmt"

	"github.com/netbrother/netbrother/internal/capture"
)

// Displayer is the abstraction over output modes.
type Displayer interface {
	// Start begins consuming events and rendering output.
	// This is a blocking call; it returns when ctx is cancelled or the
	// events channel is closed.
	Start(ctx context.Context, events <-chan capture.Event) error

	// Close tears down the display.
	Close() error
}

// LogConfig configures the log-mode display.
type LogConfig struct {
	JSON  bool
	Color bool
}

// New creates a Displayer based on the requested mode.
// mode values: "tui" (default), "log".
func New(mode string, cfg LogConfig) (Displayer, error) {
	switch mode {
	case "tui":
		return newTUDisplay()
	case "log":
		return newLogDisplayer(cfg), nil
	default:
		return nil, fmt.Errorf("unknown display mode: %q", mode)
	}
}
