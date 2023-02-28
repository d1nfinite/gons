//go:build linux

package gons

import (
	"fmt"
	"os"
	"testing"
)

func TestParseTCP(t *testing.T) {
	handle, err := os.Open("/proc/net/tcp")
	if err != nil {
		t.Error(err)
	}

	sockets, err := ParseTCP(handle)
	if err != nil {
		t.Error(err)
	}

	for _, s := range sockets {
		_ = RelateProcess(&s)
		fmt.Printf("%+v\n", s)
	}
}

func TestParseTCP6(t *testing.T) {
	handle, err := os.Open("/proc/net/tcp6")
	if err != nil {
		t.Error(err)
	}

	sockets, err := ParseTCP6(handle)
	if err != nil {
		t.Error(err)
	}

	for _, s := range sockets {
		_ = RelateProcess(&s)
		fmt.Printf("%+v\n", s)
	}
}

func TestParseUDP(t *testing.T) {
	handle, err := os.Open("/proc/net/udp")
	if err != nil {
		t.Error(err)
	}

	sockets, err := ParseUDP(handle)
	if err != nil {
		t.Error(err)
	}

	for _, s := range sockets {
		_ = RelateProcess(&s)
		fmt.Printf("%+v\n", s)
	}
}

func TestParseUDP6(t *testing.T) {
	handle, err := os.Open("/proc/net/udp6")
	if err != nil {
		t.Error(err)
	}

	sockets, err := ParseUDP6(handle)
	if err != nil {
		t.Error(err)
	}

	for _, s := range sockets {
		_ = RelateProcess(&s)
		fmt.Printf("%+v\n", s)
	}
}
