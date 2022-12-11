//go:build linux

package netstat

import (
	"net"
	"os"
	"path/filepath"
)

type SocketType int

const (
	SOCK_UNKNWON   SocketType = 0
	SOCK_DGRAM     SocketType = 1
	SOCK_STREAM    SocketType = 2
	SOCK_RAW       SocketType = 3
	SOCK_RDM       SocketType = 4
	SOCK_SEQPACKET SocketType = 5
	SOCK_PACKET    SocketType = 6
)

type SocketProtoType int

const (
	PROTO_UNKNWON SocketProtoType = 0
	PROTO_TCP     SocketProtoType = 1
	PROTO_UDP     SocketProtoType = 2
	PROTO_UDPL    SocketProtoType = 3
	PROTO_RAW     SocketProtoType = 4
)

type SocketStateType int

const (
	STATE_ESTABLISHED SocketStateType = 1
	STATE_SYN_SENT    SocketStateType = 2
	STATE_SYN_RECV    SocketStateType = 3
	STATE_FIN_WAIT1   SocketStateType = 4
	STATE_FIN_WAIT2   SocketStateType = 5
	STATE_TIME_WAIT   SocketStateType = 6
	STATE_CLOSE       SocketStateType = 7
	STATE_CLOSE_WAIT  SocketStateType = 8
	STATE_LAST_ACK    SocketStateType = 9
	STATE_LISTEN      SocketStateType = 10
	STATE_CLOSING     SocketStateType = 11
)

type SocketAddress struct {
	IP   net.IP
	Port int
}

type Socket struct {
	Proto          SocketProtoType
	State          SocketStateType
	LocalAddress   SocketAddress
	ForeignAddress SocketAddress
	RecvQ          int
	SendQ          int
	Pid            int
	ProgramName    string
	Raw            RawSocket
}

// RawSocket indicate raw socket field.
type RawSocket struct {
	fields []string
}

type SocketProtoFilter int

const (
	PROTO_TCP_FILTER  SocketProtoFilter = 1
	PROTO_TCP6_FILTER SocketProtoFilter = 1 << 1
	PROTO_UDP_FILTER  SocketProtoFilter = 1 << 2
	PROTO_UDP6_FILTER SocketProtoFilter = 1 << 3
)

var defaultFilter = func() int {
	return int(PROTO_TCP_FILTER) | int(PROTO_UDP_FILTER) | int(PROTO_TCP6_FILTER) | int(PROTO_UDP6_FILTER)
}()

type Option struct {
	procFsRoot string
	namespace  int32
	filterFlag int
}

type OptionSet func(option *Option)

func WithProcFsRoot(root string) OptionSet {
	return func(option *Option) {
		option.procFsRoot = root
	}
}

func WithFilterFlag(flag int) OptionSet {
	return func(option *Option) {
		option.filterFlag = flag
	}
}

func WithNamespace(ns int32) OptionSet {
	return func(option *Option) {
		option.namespace = ns
	}
}

func Sockets(opts ...OptionSet) ([]Socket, error) {
	o := new(Option)
	for _, fn := range opts {
		fn(o)
	}
	if o.procFsRoot == "" {
		o.procFsRoot = defaultProcFsRoot
	}
	if o.filterFlag == 0 {
		o.filterFlag = int(defaultFilter)
	}

	var (
		sockets []Socket
		devices []struct {
			path         string
			parseOptions []ParseOptionSet
			proto        SocketProtoType
		}
	)

	if o.filterFlag&int(PROTO_TCP_FILTER) != 0 {
		devices = append(devices, struct {
			path         string
			parseOptions []ParseOptionSet
			proto        SocketProtoType
		}{path: filepath.Join(o.procFsRoot, "net", "tcp"), parseOptions: []ParseOptionSet{}, proto: PROTO_TCP})
	}
	if o.filterFlag&int(PROTO_TCP6_FILTER) != 0 {
		devices = append(devices, struct {
			path         string
			parseOptions []ParseOptionSet
			proto        SocketProtoType
		}{path: filepath.Join(o.procFsRoot, "net", "tcp6"), parseOptions: []ParseOptionSet{WithIPV6()}, proto: PROTO_TCP})
	}
	if o.filterFlag&int(PROTO_UDP_FILTER) != 0 {
		devices = append(devices, struct {
			path         string
			parseOptions []ParseOptionSet
			proto        SocketProtoType
		}{path: filepath.Join(o.procFsRoot, "net", "udp"), parseOptions: []ParseOptionSet{}, proto: PROTO_UDP})
	}
	if o.filterFlag&int(PROTO_UDP6_FILTER) != 0 {
		devices = append(devices, struct {
			path         string
			parseOptions []ParseOptionSet
			proto        SocketProtoType
		}{path: filepath.Join(o.procFsRoot, "net", "udp6"), parseOptions: []ParseOptionSet{WithIPV6()}, proto: PROTO_UDP})
	}

	for _, device := range devices {
		d, err := os.Open(device.path)
		if err != nil {
			continue
		}

		parsed, err := Parse(d, device.parseOptions...)
		for index, _ := range parsed {
			err := RelateProcess(&parsed[index], opts...)
			if err != nil {
				continue
			}
			parsed[index].Proto = device.proto
		}
		sockets = append(sockets, parsed...)
	}

	return sockets, nil
}
