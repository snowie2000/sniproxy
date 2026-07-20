package main

import (
	"bufio"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/tcpproxy"
)

var (
	fastMap       = make(map[string]tcpproxy.Target)
	fastMapLock   sync.RWMutex
	fastMapNilRec int = 0
)

type HostMap map[string]host

func (this *HostMap) matchHost(hostname string, port int) (t tcpproxy.Target, found bool) {
	parseTarget := func(target string) string {
		if target[:4] == "auto" {
			aport, _ := strconv.Atoi(target[5:])
			return fmt.Sprintf("%s:%d", hostname, IfThen(aport > 0, aport, port))
		}
		return target
	}

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
		outaddr := parseTarget(h.Value)
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
			log.Println(wildhost, "=>", h.Value)
			outaddr := parseTarget(h.Value)

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
	}
	// then suffix match
	for k, v := range suffixMap {
		if strings.HasSuffix("."+hostname, k) {
			log.Println("."+hostname, "=>", v.Value)
			outaddr := parseTarget(v.Value)

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
			fastMap[hostname] = t
			return
		}
	}
	// then catch all match
	if h, ok := self["*"]; ok {
		log.Println(hostname, "*=>", h.Value)
		outaddr := parseTarget(h.Value)

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

	return nil, false // no match
}

func (this *HostMap) Match(r *bufio.Reader) (t tcpproxy.Target, targetHostName string) {
	altname := ""
	hostname := ""
	hello, err := tcpproxy.ClientHello(r)
	if err != nil {
		return nil, ""
	}
	isAcme := hello != nil && hello.SupportedProtos != nil && slices.Contains(hello.SupportedProtos, "acme-tls/1")
	hostname = IfThen(isAcme, strings.ToLower(hello.ServerName+"@acme"), strings.ToLower(hello.ServerName))
	altname = IfThen(isAcme, strings.ToLower(hello.ServerName), "")
	targetHostName = hello.ServerName

	if t, found := this.matchHost(hostname, 443); found {
		return t, targetHostName
	}
	if altname != "" {
		if t, found := this.matchHost(altname, 443); found {
			return t, targetHostName
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
