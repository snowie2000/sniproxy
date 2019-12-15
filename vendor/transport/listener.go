package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

func NewKeepAliveListener(network string, addr string, nKeepAliveTimer time.Duration) (ln net.Listener, err error) {
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		var lc net.ListenConfig
		lc.Control = listenerController()
		ctx := context.Background()
		if ln, err = lc.Listen(ctx, network, addr); err == nil {
			if tn, ok := ln.(*net.TCPListener); ok {
				return &tcpKeepAliveListener{tn, nKeepAliveTimer}, nil
			}
		}
		return
	} else {
		return nil, errors.New("Only tcp network is accepted")
	}
}

// tcpKeepAliveListener wraps a TCPListener to
// activate TCP keep alive on every accepted connection
type tcpKeepAliveListener struct {
	// inner TCPlistener
	*net.TCPListener

	// interval between keep alives to set on accepted conns
	keepAliveInterval time.Duration
}

// Accept a TCP Conn and enable TCP keep alive
func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		return
	}
	err = tc.SetKeepAlivePeriod(ln.keepAliveInterval)
	if err != nil {
		return
	}
	return tc, nil
}
