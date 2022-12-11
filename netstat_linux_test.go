package netstat

import (
	"fmt"
	"testing"
)

func TestSockets(t *testing.T) {
	sockets, err := Sockets()
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range sockets {
		fmt.Printf("%+v\n", s)
	}
}
