//+build linux

package transport

import (
	"log"
	"syscall"
)

func dialerController(mark int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if mark != 0 {
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
				if err != nil {
					log.Println("Adding mark error:", err)
				}
			}
			syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, TCP_FASTOPEN_CONNECT, 1)
		})
	}
}

func listenerController() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, TCP_FASTOPEN, 1) // 启用tcpfastopen
		})
	}
}
