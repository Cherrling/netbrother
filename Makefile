BINARY=netbrother
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build build-bpf build-nopcap build-pcap generate clean test

all: build

# Default build: pure Go, no CGO, no external deps needed
build:
	CGO_ENABLED=0 go build -o $(BINARY) $(LDFLAGS) ./cmd/netbrother/

# Build with eBPF support (requires clang + kernel BTF)
build-bpf: generate
	CGO_ENABLED=0 go build -tags bpf -o $(BINARY)-bpf $(LDFLAGS) ./cmd/netbrother/

# Build with pcap support (requires libpcap-dev + CGO)
build-pcap:
	CGO_ENABLED=1 go build -tags pcap -o $(BINARY)-pcap $(LDFLAGS) ./cmd/netbrother/

# Static build with pcap
build-static:
	CGO_ENABLED=1 go build -tags pcap -ldflags "-extldflags '-static' $(LDFLAGS)" \
		-o $(BINARY)-static ./cmd/netbrother/

# Generate BPF Go code from C source
generate:
	go generate -tags bpf ./internal/capture/

clean:
	rm -f $(BINARY) $(BINARY)-bpf $(BINARY)-pcap $(BINARY)-static

test:
	go test ./...

run: build
	./$(BINARY)

run-log: build
	./$(BINARY) -mode log

run-verbose: build
	./$(BINARY) -mode log -v
