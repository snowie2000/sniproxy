package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
)

const (
	extensionServerName uint16 = 0
)

var (
	port                  string = "443"
	errInvaildClientHello error  = errors.New("Invalid TLS ClientHello data")
)

type host struct {
	Name  string
	Value string
}

type hosts struct {
	Listen string
	Tls    []host
}

var config hosts
var hostMap map[string]string = make(map[string]string)

func main() {
	s := "config.json"
	flag.Set("logtostderr", "true")
	flag.StringVar(&s, "c", "config.json", "configuration")
	flag.Parse()

	//enable pprof
	go http.ListenAndServe("localhost:6060", nil)

	if f, err := ioutil.ReadFile(s); err == nil {
		json.Unmarshal(f, &config)
		for _, h := range config.Tls {
			hostMap[strings.ToLower(h.Name)] = h.Value
		}
	} else {
		os.Exit(-1)
	}
	ln, err := net.Listen("tcp4", config.Listen)
	_, port, _ = net.SplitHostPort(config.Listen)
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
	defer debug.FreeOSMemory()
	defer c.Close()

	var err error

	b := make([]byte, 1024)
	c.SetReadDeadline(time.Now().Add(time.Second * 30))
	n, err := io.ReadAtLeast(c, b, 48)
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
	if n, ok := hostMap[raddr]; ok {
		glog.Infof("%s ==> %s", raddr, n)
		raddr = n
	} else {
		if n, ok := hostMap[host]; ok {
			glog.Infof("%s ==> %s", host, n)
			raddr = net.JoinHostPort(n, port)
		}
	}

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

	var wg sync.WaitGroup
	wg.Add(2)
	go tunnel(c, rc, &wg)
	go tunnel(rc, c, &wg)
	wg.Wait()
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
	return strings.ToLower(serverName), nil
}

func tunnel(dst io.WriteCloser, src io.Reader, wg *sync.WaitGroup) {
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		glog.Infof("Connection close %v\n", err.Error())
	}
	wg.Done()
}
