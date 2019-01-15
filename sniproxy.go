package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"mapset"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
)

const (
	extensionServerName uint16 = 0
	KeepAliveTime              = 60 * time.Second
)

var (
	port                  string     = "443"
	errInvaildClientHello error      = errors.New("Invalid TLS ClientHello data")
	errNoEnoughData       error      = errors.New("Insufficient data provided")
	randset               mapset.Set = mapset.NewSet()
)

type host struct {
	Name  string
	Value string
}

type hosts struct {
	Listen  string
	Tls     []host
	Default string
	Acme    string
}

type buferror struct {
	required int
	err      error
}

type dataProducer struct {
	l      int
	rawbuf []byte
	outbuf []byte
	c      net.Conn
}

func (this *dataProducer) Ensure(nLen int) ([]byte, error) {
	if nLen > len(this.rawbuf) {
		return nil, errors.New("Buffer underrun")
	}
	if this.l >= nLen {
		return this.rawbuf[:this.l], nil
	} else {
		this.c.SetReadDeadline(time.Now().Add(time.Second * 30))
		size, err := io.ReadAtLeast(this.c, this.rawbuf[this.l:], nLen-this.l)
		if err != nil {
			return nil, err
		} else {
			this.l += size
			return this.rawbuf[:this.l], nil
		}
	}
}

func (this *dataProducer) Bytes() []byte {
	return this.rawbuf[:this.l]
}

var config hosts
var hostMap map[string]string = make(map[string]string)

type bufpool struct {
	p     chan []byte
	count int
}

func (this *bufpool) Get() []byte {
	var r []byte
	select {
	case r = <-this.p:
	default:
		{
			r = make([]byte, 512*1024)
			this.count++
		}
	}
	return r
}

func (this *bufpool) Put(b []byte) {
	select {
	case this.p <- b:
	default:
	}
}

func NewPool() *bufpool {
	return &bufpool{
		p:     make(chan []byte, 400),
		count: 0,
	}
}

var g_pool *bufpool = NewPool()

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

// TCPListener creates a Listener for TCP proxy server.
func TCPListener(addr string) (net.Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &tcpKeepAliveListener{ln, KeepAliveTime}, nil
}

func main() {
	s := ""
	flag.Set("logtostderr", "true")
	flag.StringVar(&s, "c", "", "configuration")
	flag.Parse()

	//enable pprof
	//http.HandleFunc("/status", PrintStatus)
	//go http.ListenAndServe("localhost:6060", nil)

	if s == "" {
		p, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		s = p + string(os.PathSeparator) + "config.json"
	}
	if f, err := ioutil.ReadFile(s); err == nil {
		json.Unmarshal(f, &config)
		var ip string
		for _, h := range config.Tls {
			ip = h.Value
			_, _, err := net.SplitHostPort(ip)
			if err == nil {
				hostMap[strings.ToLower(h.Name)] = h.Value
			}
		}
	} else {
		os.Exit(-1)
	}
	ln, err := TCPListener(config.Listen)
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
	defer c.Close()

	var err error

	bx := g_pool.Get()
	defer g_pool.Put(bx)

	reader := &dataProducer{
		rawbuf: bx,
		c:      c,
	}
	_, err = reader.Ensure(42)
	if err != nil {
		glog.Warningf("Read error: %v\n", err)
		return
	}
	//glog.Infoln("Got something", b[:n])
	var (
		host     string
		rand     string
		required int
	)
	for {
		host, rand, err, required = extractSNI(reader.Bytes())
		if err == errNoEnoughData && required > 0 {
			if _, err = reader.Ensure(required); err == nil {
				continue
			}
		}
		if err != nil {
			glog.Errorln("Error while extracing SNI", err)
			return
		}
		break
	}
	c.SetReadDeadline(time.Time{}) //disable timeout
	if randset.Contains(rand) {
		glog.Errorf("Dead loop detected!")
		return
	}
	randset.Add(rand)
	defer randset.Remove(rand)
	if err != nil {
		glog.Warningf("extractSNI error: %v\n", err)
		return
	}
	if host == "" {
		glog.Infof("extractSNI return empty host name")
		if config.Default == "" {
			return
		}
	}
	glog.Infof("extractSNI get %v", host)

	var raddr string
	if host == "" {
		raddr = config.Default
	} else {
		if n, ok := hostMap[host]; ok {
			glog.Infof("%s ==> %s", host, n)
			raddr = n
		} else {
			if strings.HasSuffix(host, ".acme.invalid") && config.Acme != "" {
				raddr = config.Acme
				glog.Infof("Acme challenge found")
			} else {
				glog.Warningln(host, "has no match record")
				return
			}
		}
	}

	rc, err := net.Dial("tcp", raddr)
	if err != nil {
		glog.Warningf("Dial %v error: %v\n", raddr, err)
		return
	}
	defer rc.Close()

	_, err = rc.Write(reader.Bytes())
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
func extractSNI(data []byte) (host string, rand string, err error, requiredLen int) {
	if !(data[0] == 0x16 && data[1] == 0x3) {
		return "", "", errInvaildClientHello, 0
	}
	initialSize := len(data)
	defer func() {
		if e := recover(); e != nil {
			if s, ok := e.(*buferror); ok && s.err == errNoEnoughData {
				err = errNoEnoughData
				requiredLen = s.required
			} else {
				glog.Errorln("Unknown error:", e)
			}
		}
	}()
	checkBuf := func(r int) {
		if r > len(data) {
			panic(&buferror{
				err:      errNoEnoughData,
				required: r - len(data) + initialSize,
			})
		}
	}
	data = data[5:]

	if len(data) < 42 {
		return "", "", errNoEnoughData, 47
	}
	rand = string(data[6:38])
	sessionIdLen := int(data[38])
	checkBuf(41 + sessionIdLen)
	if sessionIdLen > 32 {
		return "", "", errInvaildClientHello, 0
	}

	// sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return "", "", errInvaildClientHello, 0
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	checkBuf(2 + cipherSuiteLen)
	if cipherSuiteLen%2 == 1 {
		return "", "", errInvaildClientHello, 0
	}
	data = data[2+cipherSuiteLen:]
	checkBuf(1)

	compressionMethodsLen := int(data[0])
	checkBuf(1 + compressionMethodsLen)

	data = data[1+compressionMethodsLen:]

	serverName := ""

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return "", rand, nil, 0
	}
	checkBuf(2)
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	checkBuf(extensionsLength)

	for extensionsLength > 0 {
		checkBuf(4)

		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		checkBuf(length)

		d := data
		switch extension {
		case extensionServerName:
			if length < 2 {
				return "", "", errInvaildClientHello, 0
			}
			numNames := int(data[0])<<8 | int(data[1])
			data := data[2:]
			for i := 0; i < numNames; i++ {
				checkBuf(3)

				nameType := data[0]
				nameLen := int(data[1])<<8 | int(data[2])
				data = data[3:]
				checkBuf(nameLen)
				if nameType == 0 {
					serverName = string(data[0:nameLen])
					break
				}
				data = data[nameLen:]
			}
		}
		data = d[length:]
		extensionsLength -= length + 4
	}
	return strings.ToLower(serverName), rand, nil, 0
}

func tunnel(dst io.WriteCloser, src io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	defer dst.Close()
	bx := g_pool.Get()
	defer g_pool.Put(bx)

	buf := bx
	io.CopyBuffer(dst, src, buf)
}

func PrintStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("make count = %d\n", g_pool.count)))
}
