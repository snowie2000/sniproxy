package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/glog"
	"github.com/google/tcpproxy"
	"github.com/sevlyar/go-daemon"
)

const (
	extensionServerName uint16 = 0
	KeepAliveTime              = 60 * time.Second
	// For incoming connections.
	TCP_FASTOPEN = 23
	// For out-going connections.
	TCP_FASTOPEN_CONNECT = 30
	TCP_QUICKACK         = 12
	VERSION              = "v08.19"
)

var (
	port                  string     = "443"
	errInvaildClientHello error      = errors.New("Invalid TLS ClientHello data")
	errNoEnoughData       error      = errors.New("Insufficient data provided")
	randset               mapset.Set = mapset.NewSet()
	hostMap               HostMap    // extact matches and wildcard matches
	suffixMap             HostMap    //suffix matches (for hosts start with .)
	fastMap               map[string]tcpproxy.Target
	fastMapLock           sync.RWMutex
	fastMapNilRec         int = 0
	cfgpath               string
	config                hosts
	p                     tcpproxy.Proxy
	hostIPList            = mapset.NewSet()
	quickDial             = new(net.Dialer)
)

type host struct {
	Name                 string
	Value                string
	ProxyProtocolVersion int
	Acme                 bool
	Proxied              bool // true则传递proxy protocol v2报头，否则为直连
}

type hosts struct {
	Listen          string
	Tls             []host
	Proxied         bool
	Default         string
	DefaultInternal string // 仅可以从内部访问的转发，可用于dns解锁
	Hsts            bool   // true则443端口同时接受http和https，对http返回302
}

type defaultProxy struct {
	defaultServer        string
	internalServer       string
	proxyProtocolVersion int
}

func (p *defaultProxy) HandleConn(c net.Conn) {
	if p.internalServer != "" { // 有内部专用后端
		addr, err := net.ResolveTCPAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err == nil && (addr.IP.IsLoopback() || hostIPList.Contains(addr.IP.String())) { // 符合内部访问，则交给内部专用后端处理
			log.Println("[intDef]", p.internalServer)
			(&tcpproxy.DialProxy{
				Addr:        p.internalServer,
				DialTimeout: time.Second * 10,
				DialContext: quickDial.DialContext,
			}).HandleConn(c)
			return
		}
	}
	if p.defaultServer != "" { // 回落到默认后端
		log.Println("[def]", p.defaultServer)
		(&tcpproxy.DialProxy{
			Addr:                 p.defaultServer,
			DialTimeout:          time.Second * 10,
			DialContext:          quickDial.DialContext,
			ProxyProtocolVersion: p.proxyProtocolVersion,
		}).HandleConn(c)
		return
	}
	log.Println("[def] rejected visit of", c.RemoteAddr().String())
	c.Close() // 不是内部访问，并且没有配置外部使用的后端，则拒绝该连接
}

type HostMap map[string]host

func (this *HostMap) matchHost(hostname string) (t tcpproxy.Target, found bool) {
	found = true
	// try fast cache first
	if func() bool {
		fastMapLock.RLock()
		defer fastMapLock.RUnlock()
		if target, ok := fastMap[hostname]; ok {
			log.Println("[hit]", hostname)
			t = target
			return true
		}
		return false
	}() {
		return
	}

	fastMapLock.Lock()
	defer fastMapLock.Unlock()
	// firstly, try exact match
	self := *this
	if h, ok := self[hostname]; ok {
		log.Println(hostname, "=>", h.Value)
		outaddr := h.Value
		if outaddr == "auto" { // auto resolve target address
			outaddr = hostname + ":443"
		}
		t = &tcpproxy.DialProxy{
			DialTimeout:          time.Second * 10,
			Addr:                 outaddr,
			ProxyProtocolVersion: h.ProxyProtocolVersion,
			DialContext:          quickDial.DialContext,
		}
		fastMap[hostname] = t
		return
	}
	// then wildcard match
	split := strings.SplitAfterN(hostname, ".", 2)
	if len(split) > 0 {
		split[0] = "*"
		wildhost := strings.Join(split, ".")
		if h, ok := self[wildhost]; ok {
			log.Println(wildhost, "=>", h.Value)
			outaddr := h.Value
			if outaddr == "auto" { // auto resolve target address
				outaddr = hostname + ":443"
			}
			t = &tcpproxy.DialProxy{
				DialTimeout:          time.Second * 10,
				Addr:                 outaddr,
				ProxyProtocolVersion: h.ProxyProtocolVersion,
				DialContext:          quickDial.DialContext,
			}
			fastMap[hostname] = t
			return
		}
	}
	// then suffix match
	for k, v := range suffixMap {
		if strings.HasSuffix("."+hostname, k) {
			log.Println("."+hostname, "=>", v.Value)
			outaddr := v.Value
			if outaddr == "auto" { // auto resolve target address
				outaddr = hostname + ":443"
			}
			t = &tcpproxy.DialProxy{
				DialTimeout:          time.Second * 10,
				Addr:                 outaddr,
				ProxyProtocolVersion: v.ProxyProtocolVersion,
				DialContext:          quickDial.DialContext,
			}
			fastMap[hostname] = t
			return
		}
	}

	return nil, false // no match
}

func (this *HostMap) Match(r *bufio.Reader) (t tcpproxy.Target, hostname string) {
	hello, err := tcpproxy.ClientHello(r)
	if err != nil {
		return nil, ""
	}
	isAcme := hello != nil && hello.SupportedProtos != nil && slices.Contains(hello.SupportedProtos, "acme-tls/1")
	hostname = IfThen(isAcme, strings.ToLower(hello.ServerName+"@acme"), strings.ToLower(hello.ServerName))
	altname := IfThen(isAcme, strings.ToLower(hello.ServerName), "")

	if t, found := this.matchHost(hostname); found {
		return t, hello.ServerName
	}
	if altname != "" {
		if t, found := this.matchHost(altname); found {
			return t, hello.ServerName
		}
	}
	// fallback to default
	if config.Default != "" || config.DefaultInternal != "" {
		t = &defaultProxy{
			defaultServer:        config.Default,
			internalServer:       config.DefaultInternal,
			proxyProtocolVersion: IfThen(config.Proxied, 2, 0),
		}
		fastMap[hostname] = t
		return
	} else {
		if fastMapNilRec > 10000 { // if more than 10000 entries cached in the fastmap, clean nil entries.
			for k, v := range fastMap {
				if v == nil {
					delete(fastMap, k)
				}
			}
			fastMapNilRec = 0
		}
		fastMapNilRec++ //no need to worry about cocurrency, we had fastMapLock mutex in front.
		fastMap[hostname] = nil
		return nil, ""
	}
}

func loadConfig(s string) (bind string, e error) {
	if s == "" {
		p, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		s = p + string(os.PathSeparator) + "config.json"
	}
	if f, err := ioutil.ReadFile(s); err == nil {
		if err = json.Unmarshal(f, &config); err != nil {
			return "", err
		}

		hostMap = make(HostMap)
		suffixMap = make(HostMap)
		fastMap = make(map[string]tcpproxy.Target)
		fastMapNilRec = 0
		var ip string
		for _, h := range config.Tls {
			ip = h.Value
			_, _, err := net.SplitHostPort(ip)
			if err == nil || ip == "auto" {
				if h.Proxied {
					h.ProxyProtocolVersion = 2 // use ppv2 for now
				} else {
					h.ProxyProtocolVersion = 0
				}
				dest := IfThen[string](h.Acme, strings.ToLower(h.Name+"@acme"), strings.ToLower(h.Name))
				if len(h.Name) > 0 && []byte(h.Name)[0] == '.' {
					suffixMap[dest] = h
				} else {
					hostMap[dest] = h
				}
			}
		}
		return config.Listen, nil
	} else {
		return "", err
	}
}

func reloadHandler(sig os.Signal) error {
	_, err := loadConfig(cfgpath)
	if err == nil {
		glog.Infoln("configuration reloaded")
	} else {
		glog.Infoln("failed to reload configuration,", err)
	}
	return err
}

func termHandler(sig os.Signal) error {
	p.Close()
	return daemon.ErrStop
}

type connWriter struct {
	resp http.Response
	body *bytes.Buffer
}

func (c *connWriter) Header() http.Header {
	return c.resp.Header
}

func (c *connWriter) Write(b []byte) (int, error) {
	return c.body.Write(b)
}

func (c *connWriter) WriteHeader(statusCode int) {
	c.resp.StatusCode = statusCode
}

func (c *connWriter) WriteTo(conn net.Conn) error {
	c.resp.ContentLength = int64(c.body.Len())
	return c.resp.Write(conn)
}

type hstsRedirector struct{}

func (h *hstsRedirector) HandleConn(c net.Conn) {
	defer c.Close()
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err == nil {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		w := &connWriter{
			body: &bytes.Buffer{},
			resp: http.Response{
				Proto:        "HTTP/1.1",
				ProtoMajor:   1,
				ProtoMinor:   1,
				Header:       make(http.Header),
				Close:        true,
				Uncompressed: true,
			},
		}
		w.resp.Body = ioutil.NopCloser(w.body)
		http.Redirect(w, req, req.URL.String(), http.StatusMovedPermanently)
		w.WriteTo(c)
	}
}

func main() {
	logPath := ""
	foreground := false
	flag.Set("logtostderr", "true")
	flag.StringVar(&cfgpath, "c", "", "configuration")
	flag.StringVar(&logPath, "log", "", "log to file")
	flag.BoolVar(&foreground, "f", false, "run foreground")

	signal := flag.String("s", "", "signals, possible values: \"reload\", \"stop\"")
	flag.Parse()

	var cntxt *daemon.Context
	if !foreground {
		daemon.AddCommand(daemon.StringFlag(signal, "reload"), syscall.SIGUSR1, reloadHandler)
		daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)
		cntxt = &daemon.Context{
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
	}
	//enable pprof
	//go http.ListenAndServe("localhost:6666", nil)

	// prepare dialer context
	quickDial.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_QUICKACK, 1)
		})
	}

	if bind, err := loadConfig(cfgpath); err != nil {
		glog.Fatalln(err)
	} else {
		p.AddCustomRoute(bind, &hostMap)
		if config.Hsts {
			p.AddHTTPHostMatchRoute(bind, func(ctx context.Context, hostname string) bool {
				return hostname != ""
			}, &hstsRedirector{})
		}
	}
	glog.Infoln("Sniproxy (google tcpproxy version)", VERSION, "started")

	// collecting host NIC addresses
	iplist := hostAddress()
	for _, ip := range iplist {
		hostIPList.Add(ip)
		glog.Infoln("Found NIC:", ip)
	}

	if foreground {
		p.Run()
	} else {
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
			log.Println("Process exit with error", p.Run())
		}()
		daemon.ServeSignals()
	}
}

func hostAddress() (ips []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifaces {
		if addrs, err := i.Addrs(); err == nil {
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					ips = append(ips, v.IP.String())
				case *net.IPAddr:
					ips = append(ips, v.IP.String())
				}
				// process IP address
			}
		}
	}
	return
}

func IfThen[T any](condition bool, valueIfTrue T, valueIfFalse T) T {
	if condition {
		return valueIfTrue
	}
	return valueIfFalse
}
