package process

import (
	"testing"
)

func TestParseProcNetLine_Established(t *testing.T) {
	line := "  0: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
	c, ok := parseProcNetLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if c.Slot != 0 {
		t.Errorf("slot = %d, want 0", c.Slot)
	}
	if c.LocalIP != "0100007F" {
		t.Errorf("local IP = %s, want 0100007F", c.LocalIP)
	}
	if c.LocalPort != 25 {
		t.Errorf("local port = %d, want 25 (0x0019)", c.LocalPort)
	}
	if c.RemotePort != 0 {
		t.Errorf("remote port = %d, want 0", c.RemotePort)
	}
	if c.State != 0x0A {
		t.Errorf("state = %d, want 10 (0x0A)", c.State)
	}
	if c.Inode != 12345 {
		t.Errorf("inode = %d, want 12345", c.Inode)
	}
}

func TestParseProcNetLine_Listen(t *testing.T) {
	line := "  1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0"
	c, ok := parseProcNetLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if c.LocalPort != 80 {
		t.Errorf("local port = %d, want 80 (0x0050)", c.LocalPort)
	}
	if c.State != 0x0A {
		t.Errorf("state = %d, want 10 (0x0A)", c.State)
	}
	if c.Inode != 67890 {
		t.Errorf("inode = %d, want 67890", c.Inode)
	}
}

func TestParseProcNetLine_ShortLine(t *testing.T) {
	_, ok := parseProcNetLine("too short")
	if ok {
		t.Fatal("expected parse to fail for short line")
	}
}

func TestParseProcNetLine_InvalidSlot(t *testing.T) {
	line := "  x: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0"
	_, ok := parseProcNetLine(line)
	if ok {
		t.Fatal("expected parse to fail for invalid slot")
	}
}

func TestHexToIP(t *testing.T) {
	tests := []struct {
		hex  string
		want string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		{"0A000001", "1.0.0.10"},
		{"C0A80102", "2.1.168.192"},
	}

	for _, tt := range tests {
		got := HexToIP(tt.hex)
		if got != tt.want {
			t.Errorf("HexToIP(%s) = %s, want %s", tt.hex, got, tt.want)
		}
	}
}
