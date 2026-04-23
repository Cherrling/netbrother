package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/netbrother/netbrother/internal/capture"
	"github.com/netbrother/netbrother/internal/config"
	"github.com/netbrother/netbrother/internal/detect"
	"github.com/netbrother/netbrother/internal/display"
)

var version = "dev"

func main() {
	cfg, err := config.ParseFlags()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Create capturer (auto-detect: pcap -> proc)
	capturer, err := capture.New(cfg.Interface)
	if err != nil {
		log.Fatalf("no capture backend available: %v", err)
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "capture backend: %s (requires root: %v)\n",
			capturer.Name(), capturer.RequiresRoot())
	}

	// Create detector orchestrator
	detector := detect.NewOrchestrator(cfg.ToDetectorConfig())

	// Create display
	displayer, err := display.New(cfg.Mode, cfg.ToDisplayConfig())
	if err != nil {
		log.Fatalf("cannot create display: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start capture
	events, err := capturer.Start(ctx)
	if err != nil {
		log.Fatalf("cannot start capture: %v", err)
	}

	// Event processing pipeline: capture -> detect -> display
	processed := make(chan capture.Event)
	go func() {
		defer close(processed)
		for evt := range events {
			evt.Alerts = detector.Analyze(evt)
			select {
			case processed <- evt:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Run display (blocking)
	if err := displayer.Start(ctx, processed); err != nil &&
		err != context.Canceled {
		log.Fatalf("display error: %v", err)
	}
}
