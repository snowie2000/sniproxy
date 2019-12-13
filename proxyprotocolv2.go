// proxyprotocolv2
package main

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
)

var SIGV2 = [12]byte{'\x0D', '\x0A', '\x0D', '\x0A', '\x00', '\x0D', '\x0A', '\x51', '\x55', '\x49', '\x54', '\x0A'}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

type PPHeader struct {
	Header [12]byte
	VerCmd byte
	Family byte
	Len    uint16
}

type PPBody struct {
	Srcaddr uint32
	Dsraddr uint32
	Srcport uint16
	Dstport uint16
}

type PPBody6 struct {
	Srcaddr [16]byte
	Dsraddr [16]byte
	Srcport uint16
	Dstport uint16
}

func WriteProxyProtocol(c net.Conn, saddr, daddr net.Addr) {
	var (
		header = &PPHeader{
			Header: SIGV2,
			VerCmd: 0x21,
		}
		body  = &PPBody{}
		body6 = &PPBody6{}
	)
	buff := &bytes.Buffer{}
	localaddr := saddr.String()
	remoteaddr := daddr.String()
	if IsIPv4(remoteaddr) {
		header.Family = 0x11
		header.Len = 12

		if ip, e := net.ResolveTCPAddr("tcp4", remoteaddr); e == nil {
			uip := big.NewInt(0)
			uip.SetBytes([]byte(ip.IP))
			body.Dsraddr = uint32(uip.Uint64())
			body.Dstport = uint16(ip.Port)
		}
		if ip, e := net.ResolveTCPAddr("tcp4", localaddr); e == nil {
			uip := big.NewInt(0)
			uip.SetBytes([]byte(ip.IP))
			body.Srcaddr = uint32(uip.Uint64())
			body.Srcport = uint16(ip.Port)
		}
		binary.Write(buff, binary.BigEndian, header)
		binary.Write(buff, binary.BigEndian, body)
	} else {
		header.Family = 0x21 // we only support tcp stream relay
		header.Len = 36

		if ip, e := net.ResolveTCPAddr("tcp6", remoteaddr); e == nil {
			copy(body6.Dsraddr[:], ip.IP)
			body6.Dstport = uint16(ip.Port)
		}
		if ip, e := net.ResolveTCPAddr("tcp6", localaddr); e == nil {
			copy(body6.Srcaddr[:], ip.IP)
			body6.Srcport = uint16(ip.Port)
		}
		binary.Write(buff, binary.BigEndian, header)
		binary.Write(buff, binary.BigEndian, body6)
	}
	c.Write(buff.Bytes())
}
