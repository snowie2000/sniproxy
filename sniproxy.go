package main

import (
	"errors"
	"flag"
	"github.com/golang/glog"
	"io"
	"net"
	"time"
)

const (
	port                       = "443"
	extensionServerName uint16 = 0
)

var (
	errInvaildClientHello error = errors.New("Invalid TLS ClientHello data")
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		glog.Fatalf("Listen failed: %v\n", err)
	}
	glog.Infof("Listen on %s\n", ln.Addr())

	for {
		c, err := ln.Accept()
		if err != nil {
			glog.Infof("Accept error: %v\n", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go serve(c)
	}
}

func serve(c net.Conn) {
	glog.Infof("Handle connection %v\n", c.RemoteAddr())
	defer c.Close()

	var err error

	b := make([]byte, 1024)
	n, err := c.Read(b)
	if err != nil {
		glog.Warningf("Read error: %v\n", err)
		return
	}
	b = b[:n]

	host, err := extractSNI(b)
	if err != nil {
		glog.Warningf("extractSNI error: %v\n", err)
		return
	}
	if host == "" {
		glog.Infof("extractSNI return empty host name")
		return
	}
	glog.Infof("extractSNI get %v", host)

	raddr := net.JoinHostPort(host, port)
	rc, err := net.Dial("tcp", raddr)
	if err != nil {
		glog.Warningf("Dial %v error: %v\n", raddr, err)
		return
	}
	defer rc.Close()

	_, err = rc.Write(b)
	if err != nil {
		glog.Warningf("Write %v error: %v\n", rc, err)
		return
	}

	go io.Copy(c, rc)
	io.Copy(rc, c)
}

// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go
func extractSNI(data []byte) (host string, err error) {
	if !(data[0] == 0x16 && data[1] == 0x3) {
		return "", errInvaildClientHello
	}
	data = data[5:]

	if len(data) < 42 {
		return "", errInvaildClientHello
	}

	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return "", errInvaildClientHello
	}

	// sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return "", errInvaildClientHello
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return "", errInvaildClientHello
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return "", errInvaildClientHello
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return "", errInvaildClientHello
	}

	data = data[1+compressionMethodsLen:]

	serverName := ""

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return "", nil
	}
	if len(data) < 2 {
		return "", errInvaildClientHello
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return "", errInvaildClientHello
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return "", errInvaildClientHello
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return "", errInvaildClientHello
		}

		switch extension {
		case extensionServerName:
			if length < 2 {
				return "", errInvaildClientHello
			}
			numNames := int(data[0])<<8 | int(data[1])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return "", errInvaildClientHello
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return "", errInvaildClientHello
				}
				if nameType == 0 {
					serverName = string(d[0:nameLen])
					break
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}
	return serverName, nil
}
