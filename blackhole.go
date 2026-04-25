package main

import "net"

type BlackHoleTarget struct {
}

func (b *BlackHoleTarget) HandleConn(c net.Conn) {
	c.Close()
}
