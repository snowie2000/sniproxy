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
	"mapset"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

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
	VERSION              = "v10.31"
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
)

type host struct {
	Name                 string
	Value                string
	ProxyProtocolVersion int
	Proxied              bool // true则传递proxy protocol v2报头，否则为直连
}

type hosts struct {
	Listen          string
	Tls             []host
	Default         string
	DefaultInternal string // 仅可以从内部访问的转发，可用于dns解锁
	Hsts            bool   // true则443端口同时接受http和https，对http返回302
}

type defaultProxy struct {
	defaultServer  string
	internalServer string
}

func (p *defaultProxy) HandleConn(c net.Conn) {
	if p.internalServer != "" { // 有内部专用后端
		addr, err := net.ResolveTCPAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err == nil && addr.IP.IsLoopback() { // 符合内部访问，则交给内部专用后端处理
			log.Println("[intDef]", p.internalServer)
			(&tcpproxy.DialProxy{
				Addr:        p.internalServer,
				DialTimeout: time.Second * 10,
			}).HandleConn(c)
			return
		}
	}
	if p.defaultServer != "" { // 回落到默认后端
		log.Println("[def]", p.defaultServer)
		(&tcpproxy.DialProxy{
			Addr:        p.defaultServer,
			DialTimeout: time.Second * 10,
		}).HandleConn(c)
		return
	}
	log.Println("[def] rejected visit of", c.RemoteAddr().String())
	c.Close() // 不是内部访问，并且没有配置外部使用的后端，则拒绝该连接
}

type HostMap map[string]host

func (this *HostMap) Match(r *bufio.Reader) (t tcpproxy.Target, hostname string) {
	sni, err := tcpproxy.ClientHelloServerName(r)
	if err != nil {
		return nil, ""
	}
	hostname = strings.ToLower(sni)

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
		t = &tcpproxy.DialProxy{
			DialTimeout:          time.Second * 10,
			Addr:                 h.Value,
			ProxyProtocolVersion: h.ProxyProtocolVersion,
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
			t = &tcpproxy.DialProxy{
				DialTimeout:          time.Second * 10,
				Addr:                 h.Value,
				ProxyProtocolVersion: h.ProxyProtocolVersion,
			}
			fastMap[hostname] = t
			return
		}
	}
	// then suffix match
	for k, v := range suffixMap {
		if strings.HasSuffix("."+hostname, k) {
			log.Println("."+hostname, "=>", v.Value)
			t = &tcpproxy.DialProxy{
				DialTimeout:          time.Second * 10,
				Addr:                 v.Value,
				ProxyProtocolVersion: v.ProxyProtocolVersion,
			}
			fastMap[hostname] = t
			return
		}
	}

	// fallback to default
	if config.Default != "" || config.DefaultInternal != "" {
		t = &defaultProxy{
			defaultServer:  config.Default,
			internalServer: config.DefaultInternal,
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
			if h.Name == "" {
				continue
			}
			ip = h.Value
			_, _, err := net.SplitHostPort(ip)
			if err == nil {
				if h.Proxied {
					h.ProxyProtocolVersion = 2 // use ppv2 for now
				} else {
					h.ProxyProtocolVersion = 0
				}
				if []byte(h.Name)[0] == '.' {
					suffixMap[strings.ToLower(h.Name)] = h
				} else {
					hostMap[strings.ToLower(h.Name)] = h
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
	go http.ListenAndServe("localhost:6666", nil)

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
