package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netbrother/netbrother/internal/detect"
	"github.com/netbrother/netbrother/internal/display"
)

// Config holds all configuration for netbrother.
type Config struct {
	Mode         string
	Interface    string
	Rate         time.Duration
	JSON         bool
	Verbose      bool
	BadPorts     []detect.PortRange
	BadIPs       []string
	Window       time.Duration
	MinSamples   int
	CVThreshold  float64
	Keep         bool
	Output       string
	ShowTimeWait bool
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Mode:        "tui",
		Interface:   "eth0",
		Rate:        1 * time.Second,
		JSON:        true,
		Verbose:     false,
		BadPorts:    detect.DefaultBadPorts(),
		Window:      5 * time.Minute,
		MinSamples:  3,
		CVThreshold: 0.25,
	}
}

// ParseFlags parses command-line flags and returns a Config.
func ParseFlags() (Config, error) {
	cfg := DefaultConfig()

	mode := flag.String("mode", cfg.Mode, "Display mode: tui or log")
	iface := flag.String("i", cfg.Interface, "Network interface (for pcap mode)")
	rate := flag.Duration("rate", cfg.Rate, "Polling interval for /proc mode")
	json := flag.Bool("json", cfg.JSON, "JSON output in log mode")
	verbose := flag.Bool("v", cfg.Verbose, "Verbose logging")
	badPorts := flag.String("bad-ports", "", "Comma-separated port ranges to flag (e.g. 4444,1337,6660-6669)")
	badIPs := flag.String("bad-ips", "", "Comma-separated CIDR ranges to flag")
	window := flag.Duration("window", cfg.Window, "Sliding window for periodic detection")
	minSamples := flag.Int("min-samples", cfg.MinSamples, "Min connections before periodic detection activates")
	cvThreshold := flag.Float64("cv-threshold", cfg.CVThreshold, "Max coefficient of variation for beacon detection")
	keep := flag.Bool("keep", cfg.Keep, "Keep closed connections visible in TUI")
	output := flag.String("output", cfg.Output, "Save all connections to file (table format)")
	showTimeWait := flag.Bool("show-time-wait", cfg.ShowTimeWait, "Show TIME_WAIT connections")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Println("netbrother v0.1.0")
		os.Exit(0)
	}

	cfg.Mode = *mode
	cfg.Interface = *iface
	cfg.Rate = *rate
	cfg.JSON = *json
	cfg.Verbose = *verbose
	cfg.Window = *window
	cfg.MinSamples = *minSamples
	cfg.CVThreshold = *cvThreshold
	cfg.Keep = *keep
	cfg.Output = *output
	cfg.ShowTimeWait = *showTimeWait

	if *badPorts != "" {
		ports, err := parsePortRanges(*badPorts)
		if err != nil {
			return cfg, fmt.Errorf("bad-ports: %w", err)
		}
		cfg.BadPorts = ports
	}

	if *badIPs != "" {
		ips := strings.Split(*badIPs, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				_, _, err := net.ParseCIDR(ip)
				if err != nil {
					return cfg, fmt.Errorf("bad-ips: invalid CIDR %q: %w", ip, err)
				}
				cfg.BadIPs = append(cfg.BadIPs, ip)
			}
		}
	}

	return cfg, nil
}

// ToDetectorConfig converts the global config to a detector config.
func (c Config) ToDetectorConfig() detect.Config {
	return detect.Config{
		BadPorts:    c.BadPorts,
		BadIPs:      c.BadIPs,
		Window:      int(c.Window.Seconds()),
		MinSamples:  c.MinSamples,
		CVThreshold: c.CVThreshold,
	}
}

// ToDisplayConfig converts the global config to a display config.
func (c Config) ToDisplayConfig() display.Config {
	return display.Config{
		Keep:         c.Keep,
		Output:       c.Output,
		ShowTimeWait: c.ShowTimeWait,
	}
}

// ToLogConfig converts the global config to a log display config.
func (c Config) ToLogConfig() display.LogConfig {
	return display.LogConfig{}
}

func parsePortRanges(s string) ([]detect.PortRange, error) {
	parts := strings.Split(s, ",")
	ranges := make([]detect.PortRange, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			ends := strings.SplitN(part, "-", 2)
			start, err := strconv.ParseUint(strings.TrimSpace(ends[0]), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", ends[0], err)
			}
			end, err := strconv.ParseUint(strings.TrimSpace(ends[1]), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", ends[1], err)
			}
			ranges = append(ranges, detect.PortRange{Start: uint16(start), End: uint16(end)})
		} else {
			port, err := strconv.ParseUint(part, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			ranges = append(ranges, detect.PortRange{Start: uint16(port), End: uint16(port)})
		}
	}

	return ranges, nil
}
