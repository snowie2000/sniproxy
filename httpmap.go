package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/tcpproxy"
)

var (
	fastHttpMap       = make(map[string]tcpproxy.Target)
	fastHttpMapLock   sync.RWMutex
	fastHttpMapNilRec int = 0
)

type HttpMap map[string]host

func (this *HttpMap) matchHost(hostname string, port int) (t tcpproxy.Target, found bool) {
	found = true
	// try fast cache first
	if func() bool {
		fastHttpMapLock.RLock()
		defer fastHttpMapLock.RUnlock()
		if target, ok := fastHttpMap[hostname]; ok {
			log.Println("[http hit]", hostname)
			t = target
			return true
		}
		return false
	}() {
		return
	}

	fastHttpMapLock.Lock()
	defer fastHttpMapLock.Unlock()
	// firstly, try exact match
	self := *this
	if h, ok := self[hostname]; ok {
		log.Println("[http]", hostname, "=>", h.Value)
		outaddr := h.Value
		if outaddr == "auto" { // auto resolve target address
			outaddr = fmt.Sprintf("%s:%d", hostname, port)
		}
		if isLoopUDP(outaddr) {
			t = blackHole // avoid loopback
		} else {
			t = &tcpproxy.DialProxy{
				DialTimeout:          time.Second * 10,
				Addr:                 outaddr,
				ProxyProtocolVersion: h.ProxyProtocolVersion,
				DialContext:          getProxy(h.ProxyServer),
			}
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
			log.Println("[http]", wildhost, "=>", h.Value)
			outaddr := h.Value
			if outaddr == "auto" { // auto resolve target address
				outaddr = hostname + ":80"
			}
			if isLoopUDP(outaddr) {
				t = blackHole // avoid loopback
			} else {
				t = &tcpproxy.DialProxy{
					DialTimeout:          time.Second * 10,
					Addr:                 outaddr,
					ProxyProtocolVersion: h.ProxyProtocolVersion,
					DialContext:          getProxy(h.ProxyServer),
				}
			}

			fastHttpMap[hostname] = t
			return
		}
	}
	// then suffix match
	for k, v := range suffixMap {
		if strings.HasSuffix("."+hostname, k) {
			log.Println("[http]", "."+hostname, "=>", v.Value)
			outaddr := v.Value
			if outaddr == "auto" { // auto resolve target address
				outaddr = hostname + ":80"
			}
			if isLoopUDP(outaddr) {
				t = blackHole // avoid loopback
			} else {
				t = &tcpproxy.DialProxy{
					DialTimeout:          time.Second * 10,
					Addr:                 outaddr,
					ProxyProtocolVersion: v.ProxyProtocolVersion,
					DialContext:          getProxy(v.ProxyServer),
				}
			}
			fastHttpMap[hostname] = t
			return
		}
	}
	// then catch all match
	if h, ok := self["*"]; ok {
		log.Println(hostname, "*=>", h.Value)
		outaddr := h.Value
		if outaddr == "auto" { // auto resolve target address
			outaddr = fmt.Sprintf("%s:%d", hostname, port)
		}
		if isLoopUDP(outaddr) {
			t = blackHole // avoid loopback
		} else {
			t = &tcpproxy.DialProxy{
				DialTimeout:          time.Second * 10,
				Addr:                 outaddr,
				ProxyProtocolVersion: h.ProxyProtocolVersion,
				DialContext:          getProxy(h.ProxyServer),
			}
		}
		fastHttpMap[hostname] = t
		return
	}

	return nil, false // no match
}

func (this *HttpMap) Match(r *bufio.Reader) (t tcpproxy.Target, targetHostName string) {
	hostname := httpHostHeader(r)
	if hostname == "" {
		return nil, ""
	}

	if t, found := this.matchHost(hostname, 80); found {
		return t, hostname
	}

	// fallback to default
	if config.Default != "" || config.DefaultInternal != "" {
		t = &defaultProxy{
			defaultServer:        config.Default,
			internalServer:       config.DefaultInternal,
			proxyProtocolVersion: IfThen(config.Proxied, 2, 0),
		}
		fastHttpMap[hostname] = t
		return
	} else {
		if fastHttpMapNilRec > 10000 { // if more than 10000 entries cached in the fastmap, clean nil entries.
			for k, v := range fastHttpMap {
				if v == nil {
					delete(fastHttpMap, k)
				}
			}
			fastHttpMapNilRec = 0
		}
		fastHttpMapNilRec++ //no need to worry about cocurrency, we had fastHttpMapLock mutex in front.
		fastHttpMap[hostname] = nil
		return nil, ""
	}
}

var (
	lfHostColon = []byte("\nHost:")
	lfhostColon = []byte("\nhost:")
	crlf        = []byte("\r\n")
	lf          = []byte("\n")
	crlfcrlf    = []byte("\r\n\r\n")
	lflf        = []byte("\n\n")
)

// untilEOL returns v, truncated before the first '\n' byte, if any.
// The returned slice may include a '\r' at the end.
func untilEOL(v []byte) []byte {
	if i := bytes.IndexByte(v, '\n'); i != -1 {
		return v[:i]
	}
	return v
}

func httpHostHeaderFromBytes(b []byte) string {
	if i := bytes.Index(b, lfHostColon); i != -1 {
		return string(bytes.TrimSpace(untilEOL(b[i+len(lfHostColon):])))
	}
	if i := bytes.Index(b, lfhostColon); i != -1 {
		return string(bytes.TrimSpace(untilEOL(b[i+len(lfhostColon):])))
	}
	return ""
}

// httpHostHeader returns the HTTP Host header from br without
// consuming any of its bytes. It returns "" if it can't find one.
func httpHostHeader(br *bufio.Reader) string {
	const maxPeek = 4 << 10
	peekSize := 0
	for {
		peekSize++
		if peekSize > maxPeek {
			b, _ := br.Peek(br.Buffered())
			return httpHostHeaderFromBytes(b)
		}
		b, err := br.Peek(peekSize)
		if n := br.Buffered(); n > peekSize {
			b, _ = br.Peek(n)
			peekSize = n
		}
		if len(b) > 0 {
			if b[0] < 'A' || b[0] > 'Z' {
				// Doesn't look like an HTTP verb
				// (GET, POST, etc).
				return ""
			}
			if bytes.Index(b, crlfcrlf) != -1 || bytes.Index(b, lflf) != -1 {
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
				if err != nil {
					return ""
				}
				if len(req.Header["Host"]) > 1 {
					// TODO(bradfitz): what does
					// ReadRequest do if there are
					// multiple Host headers?
					return ""
				}
				return req.Host
			}
		}
		if err != nil {
			return httpHostHeaderFromBytes(b)
		}
	}
}
