//go:build linux
// +build linux

package gons

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type ParseOptionSet func(option *ParseOption)

type ParseOption struct {
	ipv6 bool
}

func WithIPV6() ParseOptionSet {
	return func(option *ParseOption) {
		option.ipv6 = true
	}
}

// ParseTCP parse tcp connections from proc filesystem.
func ParseTCP(device io.Reader) ([]Socket, error) {
	sockets, err := Parse(device)
	if err != nil {
		return nil, err
	}

	for index, _ := range sockets {
		sockets[index].Proto = PROTO_TCP
	}

	return sockets, nil
}

// ParseTCP6 parse tcp6 connections from proc filesystem.
func ParseTCP6(device io.Reader) ([]Socket, error) {
	sockets, err := Parse(device, WithIPV6())
	if err != nil {
		return nil, err
	}

	for index, _ := range sockets {
		sockets[index].Proto = PROTO_TCP
	}

	return sockets, nil
}

// ParseUDP parse udp connections from proc filesystem.
func ParseUDP(device io.Reader) ([]Socket, error) {
	sockets, err := Parse(device)
	if err != nil {
		return nil, err
	}

	for index, _ := range sockets {
		sockets[index].Proto = PROTO_UDP
	}

	return sockets, nil
}

// ParseUDP6 parse udp6 connections from proc filesystem.
func ParseUDP6(device io.Reader) ([]Socket, error) {
	sockets, err := Parse(device, WithIPV6())
	if err != nil {
		return nil, err
	}

	for index, _ := range sockets {
		sockets[index].Proto = PROTO_UDP
	}

	return sockets, nil
}

// Parse parse connections from proc filesystem.
func Parse(device io.Reader, opts ...ParseOptionSet) ([]Socket, error) {
	o := new(ParseOption)
	for _, fn := range opts {
		fn(o)
	}

	scanner := bufio.NewScanner(device)
	var sockets []Socket
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 12 {
			continue
		} else if fields[0] == "sl" {
			continue
		}

		var socket Socket

		// raw
		socket.Raw = RawSocket{
			fields: fields,
		}

		var err error

		// local address
		socket.LocalAddress.IP, socket.LocalAddress.Port, err = parseIPPort(fields[1])
		if err != nil {
			continue
		}

		// foreign address
		socket.ForeignAddress.IP, socket.ForeignAddress.Port, err = parseIPPort(fields[2])
		if err != nil {
			continue
		}

		// state
		state, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			continue
		}
		socket.State = SocketStateType(state)

		// recv-q & send-q
		split := strings.Split(fields[4], ":")
		if len(split) != 2 {
			continue
		}

		recvq, err := strconv.ParseInt(split[0], 16, 32)
		if err != nil {
			continue
		}
		sendq, err := strconv.ParseInt(split[1], 16, 32)
		if err != nil {
			continue
		}

		socket.RecvQ = int(recvq)
		socket.SendQ = int(sendq)

		sockets = append(sockets, socket)
	}

	return sockets, nil
}

func parseIPPort(ipport string) (ip net.IP, port int, err error) {
	split := strings.Split(ipport, ":")
	if len(split) != 2 {
		return nil, 0, &net.ParseError{
			Type: "invalid format",
			Text: fmt.Sprintf("ipport string %q can only have 1 colon", ipport),
		}
	}
	ipStr, portStr := split[0], split[1]

	switch len(ipStr) {
	case 8:
		ip, err = parseIPv4(ipStr)
	case 32:
		ip, err = parseIPv6(ipStr)
	default:
		err = &net.ParseError{
			Type: "IP address",
			Text: fmt.Sprintf("len of ip string %q invalid", ipStr),
		}
	}
	if err != nil {
		return nil, 0, err
	}

	p, err := strconv.ParseInt(portStr, 16, 32)
	if err != nil {
		return nil, 0, err
	}

	return ip, int(p), err
}

func parseIPv4(ips string) (net.IP, error) {
	v, err := strconv.ParseUint(ips, 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make([]byte, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return ip, nil
}

func parseIPv6(ips string) (net.IP, error) {
	if len([]byte(ips)) != 32 {
		return nil, errors.New("parse: ipv6 length not match")
	}
	ip := make([]byte, net.IPv6len)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(ips[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return nil, err
		}

		binary.LittleEndian.PutUint32(ip[i*4:], uint32(v))
	}
	return ip, nil
}
