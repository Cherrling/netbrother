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
	"github.com/netbrother/netbrother/internal/process"
	"github.com/netbrother/netbrother/internal/types"
)

var version = "dev"

func main() {
	cfg, err := config.ParseFlags()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.ShowVersion {
		fmt.Printf("%s\nbackends: %v\n", version, capture.AvailableBackends())
		os.Exit(0)
	}

	capturer, err := capture.New(cfg.Interface)
	if err != nil {
		log.Fatalf("no capture backend available: %v", err)
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "capture backend: %s (requires root: %v)\n",
			capturer.Name(), capturer.RequiresRoot())
	}

	detector := detect.NewOrchestrator(cfg.ToDetectorConfig())

	displayer, err := display.New(cfg.Mode, cfg.ToDisplayConfig(), cfg.ToLogConfig())
	if err != nil {
		log.Fatalf("cannot create display: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	events, err := capturer.Start(ctx)
	if err != nil {
		log.Fatalf("cannot start capture: %v", err)
	}

	// Event processing pipeline: capture -> detect -> display
	processed := make(chan capture.Event)
	detectorOut := processed // save value, not variable (avoid closure capture bug)
	go func() {
		defer close(detectorOut)
		for evt := range events {
			evt.Alerts = detector.Analyze(evt)
			select {
			case detectorOut <- evt:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Optional: write all events to a file before forwarding to display
	var outputFile *os.File
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			log.Fatalf("output file: %v", err)
		}
		defer f.Close()
		outputFile = f

		fmt.Fprintf(outputFile, "%-22s  %-22s  %-8s  %-20s  %s\n",
			"LOCAL", "REMOTE", "PID", "PROC", "EXE")
		fmt.Fprintln(outputFile, "----------------------  ----------------------  --------  --------------------  --------")

		showTimeWait := cfg.ShowTimeWait
		written := make(map[types.ConnectionKey]bool)
		original := processed
		processed = make(chan capture.Event)
		go func() {
			defer close(processed)
			for evt := range original {
				conn := evt.Connection
				if !showTimeWait && conn.State == types.StateTimeWait {
					select {
					case processed <- evt:
					case <-ctx.Done():
						return
					}
					continue
				}
				key := conn.Key()
				if written[key] {
					select {
					case processed <- evt:
					case <-ctx.Done():
						return
					}
					continue
				}
				written[key] = true
				exePath, _ := process.ProcessExePath(conn.PID)
				local := fmt.Sprintf("%s:%d", conn.LocalIP, conn.LocalPort)
				remote := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)
				fmt.Fprintf(outputFile, "%-22s  %-22s  %-8d  %-20s  %s\n",
					local, remote,
					conn.PID, conn.ProcessName, exePath)
				select {
				case processed <- evt:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	if err := displayer.Start(ctx, processed); err != nil &&
		err != context.Canceled {
		log.Fatalf("display error: %v", err)
	}

	if outputFile != nil {
		outputFile.Sync()
	}
}
