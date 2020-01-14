package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"mapset"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"transport"

	"github.com/sevlyar/go-daemon"

	"github.com/golang/glog"
)

const (
	extensionServerName uint16 = 0
	KeepAliveTime              = 60 * time.Second
	// For incoming connections.
	TCP_FASTOPEN = 23
	// For out-going connections.
	TCP_FASTOPEN_CONNECT = 30
)

var (
	port                  string     = "443"
	errInvaildClientHello error      = errors.New("Invalid TLS ClientHello data")
	errNoEnoughData       error      = errors.New("Insufficient data provided")
	randset               mapset.Set = mapset.NewSet()
)

type host struct {
	Name    string
	Value   string
	Proxied bool // true则传递proxy protocol v2报头，否则为直连
}

type hosts struct {
	Listen  string
	Tls     []host
	Default string
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

type staticHostMap map[string]host
type wildcardHostMap map[string]host

func (this wildcardHostMap) Match(hostname string) (host, bool) {
	split := strings.SplitAfterN(hostname, ".", 2)
	split[0] = "*"
	hostname = strings.Join(split, ".")
	if h, ok := this[hostname]; ok {
		return h, true
	} else {
		return host{}, false
	}
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

var (
	config      hosts
	dialer      *net.Dialer
	hostMap     staticHostMap
	wildHostMap wildcardHostMap
	cfgpath     = ""
)

var g_pool sync.Pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1.5*1024)
	},
}

func loadConfig(s string) error {
	if s == "" {
		p, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		s = p + string(os.PathSeparator) + "config.json"
	}
	if f, err := ioutil.ReadFile(s); err == nil {
		if err = json.Unmarshal(f, &config); err != nil {
			return err
		}

		hostMap = make(staticHostMap)
		wildHostMap = make(wildcardHostMap)
		var ip string
		for _, h := range config.Tls {
			ip = h.Value
			_, _, err := net.SplitHostPort(ip)
			if err == nil {
				if strings.Contains(h.Name, "*") {
					wildHostMap[strings.ToLower(h.Name)] = h // it's a wildcard match
				} else {
					hostMap[strings.ToLower(h.Name)] = h
				}
			}
		}
		return nil
	} else {
		return err
	}
}

func reloadHandler(sig os.Signal) error {
	err := loadConfig(cfgpath)
	if err == nil {
		glog.Infoln("configuration reloaded")
	} else {
		glog.Infoln("failed to reload configuration,", err)
	}
	return err
}

func termHandler(sig os.Signal) error {
	return daemon.ErrStop
}

func main() {
	logPath := ""
	flag.Set("logtostderr", "true")
	flag.StringVar(&cfgpath, "c", "", "configuration")
	flag.StringVar(&logPath, "log", "", "log to file")
	signal := flag.String("s", "", "signals, possible values: \"reload\", \"stop\"")
	flag.Parse()

	daemon.AddCommand(daemon.StringFlag(signal, "reload"), syscall.SIGUSR1, reloadHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)
	cntxt := &daemon.Context{
		PidFileName: "sniproxy.pid",
		PidFilePerm: 0644,
		LogFileName: logPath,
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        []string{},
	}
	// send command to daemon if specified
	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			glog.Fatalf("Unable send signal to the daemon: %s", err.Error())
		}
		daemon.SendCommands(d)
		return
	}

	//enable pprof
	//http.HandleFunc("/status", PrintStatus)
	//go http.ListenAndServe("localhost:6060", nil)

	if err := loadConfig(cfgpath); err != nil {
		glog.Fatalln(err)
	}
	ln, err := transport.NewKeepAliveListener("tcp", config.Listen, KeepAliveTime)
	_, port, _ = net.SplitHostPort(config.Listen)
	if err != nil {
		glog.Fatalf("Listen failed: %v\n", err)
	}
	glog.Infof("Listen on %s\n", ln.Addr())

	glog.Infoln("Sniproxy started")
	// make a daemon process
	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatalln(err)
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	go func() {
		dialer = transport.NewMarkedDialer(&net.Dialer{
			Timeout:   time.Second * 15,
			KeepAlive: KeepAliveTime,
		}, 0)
		for {
			c, err := ln.Accept()
			if err != nil {
				glog.Infof("Accept error: %v\n", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go serve(c)
		}
	}()

	daemon.ServeSignals()
}

func serve(c net.Conn) {
	glog.Infof("Handle connection %v\n", c.RemoteAddr())
	defer c.Close()

	var err error

	bx := g_pool.Get().([]byte)
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
	var proxied bool = false // 默认禁止ppv2
	if host == "" {
		raddr = config.Default
	} else {
		if n, ok := hostMap[host]; ok {
			glog.Infof("exact match %s ==> %s", host, n.Value)
			raddr = n.Value
			proxied = n.Proxied
		} else {
			if h, ok := wildHostMap.Match(host); ok {
				glog.Infof("wildcard match %s ==> %s", host, h.Value)
				raddr = h.Value
				proxied = h.Proxied
			} else {
				glog.Warningln(host, "has no match record")
				return
			}
		}
	}

	rc, err := dialer.Dial("tcp", raddr)
	if err != nil {
		glog.Warningf("Dial %v error: %v\n", raddr, err)
		return
	}
	defer rc.Close()

	// if proxy procotol is requested, send it
	if proxied {
		WriteProxyProtocol(rc, c.RemoteAddr(), c.LocalAddr())
	}

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

	io.Copy(dst, src)
}

func PrintStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.WriteHeader(200)
}
