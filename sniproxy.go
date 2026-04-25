package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	// _ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/glog"
	"github.com/google/tcpproxy"
	"github.com/sevlyar/go-daemon"
	"golang.org/x/net/proxy"
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

type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

func makeProxyDialer(proxyServer string) Dialer {
	if strings.HasPrefix(proxyServer, "http://") {
		u, e := url.Parse(proxyServer)
		if e == nil {
			proxyServer = u.Host
			return func(ctx context.Context, network, address string) (net.Conn, error) {
				log.Println("Connect via proxy:", proxyServer)
				// 1. Dial the proxy server itself
				var d net.Dialer
				conn, err := d.DialContext(ctx, "tcp", proxyServer)
				if err != nil {
					return nil, err
				}

				// 2. Send the HTTP CONNECT request
				req, err := http.NewRequestWithContext(ctx, "CONNECT", "http://"+address, nil)
				if err != nil {
					conn.Close()
					return nil, err
				}
				req.Write(conn)

				// 3. Read the proxy response
				resp, err := http.ReadResponse(bufio.NewReader(conn), req)
				if err != nil {
					conn.Close()
					return nil, err
				}
				if resp.StatusCode != http.StatusOK {
					conn.Close()
					return nil, fmt.Errorf("proxy refused connection: %s", resp.Status)
				}

				// 4. Return the hijacked connection to tcpproxy
				return conn, nil
			}
		}
	}
	if strings.HasPrefix(proxyServer, "socks5://") {
		u, e := url.Parse(proxyServer)
		if e == nil {
			proxyServer = u.Host
			return func(ctx context.Context, network, address string) (net.Conn, error) {
				log.Println("Connect via proxy:", proxyServer)
				// Create a SOCKS5 dialer
				// proxy.Direct is the forwarder used for the initial connection to the proxy itself
				d, err := proxy.SOCKS5("tcp", proxyServer, nil, proxy.Direct)
				if err != nil {
					return nil, err
				}

				// If the dialer supports Context (it usually does), use it
				if cd, ok := d.(proxy.ContextDialer); ok {
					return cd.DialContext(ctx, network, address)
				}

				// Fallback for dialers without context support
				return d.Dial(network, address)
			}
		}
	}
	return (&net.Dialer{}).DialContext
}

var (
	port                  string     = "443"
	errInvaildClientHello error      = errors.New("Invalid TLS ClientHello data")
	errNoEnoughData       error      = errors.New("Insufficient data provided")
	randset               mapset.Set = mapset.NewSet()
	hostMap               HostMap    // extact matches and wildcard matches
	suffixMap             HostMap    //suffix matches (for hosts start with .)
	httpMap               HttpMap
	httpSuffixMap         HttpMap
	cfgpath               string
	config                hosts
	p                     tcpproxy.Proxy
	blackHole             = &BlackHoleTarget{}
	hostIPList            = mapset.NewSet()
	quickDial             = new(net.Dialer)
	proxyServers          = make(map[string]Dialer)
)

type host struct {
	Name                 string
	Value                string
	ProxyProtocolVersion int
	ProxyServer          string
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
	HttpProxy       bool   // true则开启80端口http代理功能，和hsts冲突
}

type defaultProxy struct {
	defaultServer        string
	internalServer       string
	proxyProtocolVersion int
}

const (
	protoUnknown = 0
	protoHttp    = 1
	protoHttps   = 2
)

func getProxy(proxyStr string) Dialer {
	if proxyStr == "" {
		return quickDial.DialContext
	}
	if p, ok := proxyServers[proxyStr]; ok {
		return p
	}
	return quickDial.DialContext
}

func getStreamType(r *bufio.Reader) (int, error) {
	// Peek the first byte to determine protocol
	// We use a small peek first to avoid issues with empty buffers
	protoPeek, err := r.Peek(1)
	if err != nil {
		return protoUnknown, err
	}

	// 0x16 is the TLS Handshake record type
	if protoPeek[0] == 0x16 {
		return protoHttps, nil
	}

	if protoPeek[0] >= 0x32 && protoPeek[0] <= 0x7e {
		return protoHttp, nil
	}
	return protoUnknown, fmt.Errorf("unknown proto: %d", protoPeek[0])
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

func loadConfig(s string) (bind string, e error) {
	if s == "" {
		p, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		s = p + string(os.PathSeparator) + "config.json"
	}
	if f, err := os.ReadFile(s); err == nil {
		if err = json.Unmarshal(f, &config); err != nil {
			return "", err
		}

		// rebuild cache on load
		hostMap = make(HostMap)
		suffixMap = make(HostMap)
		httpMap = make(HttpMap)
		httpSuffixMap = make(HttpMap)
		fastMap = make(map[string]tcpproxy.Target)
		fastHttpMap = make(map[string]tcpproxy.Target)

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
				if h.ProxyServer != "" && proxyServers[h.ProxyServer] == nil {
					proxyServers[h.ProxyServer] = makeProxyDialer(h.ProxyServer)
				}
				dest := IfThen(h.Acme, strings.ToLower(h.Name+"@acme"), strings.ToLower(h.Name))
				if len(h.Name) > 0 && []byte(h.Name)[0] == '.' {
					suffixMap[dest] = h
					httpSuffixMap[dest] = h
				} else {
					hostMap[dest] = h
					httpMap[dest] = h
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

func isLoopUDP(targetAddr string) bool {
	resolved, _ := net.ResolveUDPAddr("udp", targetAddr)
	log.Println(targetAddr, "resolves to", resolved)
	if resolved.IP.IsLoopback() || resolved.IP.IsPrivate() {
		return false // we actually allow direct connection to localhost
	}
	// 1. Listen on a random UDP port
	pc, _ := net.ListenPacket("udp", ":0")
	defer pc.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	// 2. Send the "Bottle" to the target
	nonce := []byte(fmt.Sprintf("loop-check-%s-%d", port, time.Now().UnixNano()))
	targetUDP, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(resolved.IP.String(), port))
	pc.WriteTo(nonce, targetUDP)

	// 3. Wait a tiny bit to see if it comes back to us
	buffer := make([]byte, 64)
	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, _, err := pc.ReadFrom(buffer)

	return err == nil && string(buffer[:n]) == string(nonce)
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
		if config.HttpProxy {
			host, _, _ := net.SplitHostPort(bind)
			p.AddCustomRoute(host+":80", &httpMap)
		} else if config.Hsts {
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
