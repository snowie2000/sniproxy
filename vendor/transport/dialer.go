package transport

import (
	"net"
)

const (
	// For incoming connections.
	TCP_FASTOPEN = 23
	// For out-going connections.
	TCP_FASTOPEN_CONNECT = 30
)

func NewMarkedDialer(dialer *net.Dialer, mark int) *net.Dialer {
	dialer.Control = dialerController(mark)
	return dialer
}
