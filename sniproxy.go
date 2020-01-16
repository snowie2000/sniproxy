package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"mapset"
	"net"
	"os"
	"path/filepath"
	"strings"
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
)

var (
	port                  string     = "443"
	errInvaildClientHello error      = errors.New("Invalid TLS ClientHello data")
	errNoEnoughData       error      = errors.New("Insufficient data provided")
	randset               mapset.Set = mapset.NewSet()
	hostMap               HostMap
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
	Listen  string
	Tls     []host
	Default string
}

type HostMap map[string]host

func (this *HostMap) Match(r *bufio.Reader) (tcpproxy.Target, string) {
	hostname := strings.ToLower(tcpproxy.ClientHelloServerName(r))
	// firstly, try exact match
	self := *this
	if h, ok := self[hostname]; ok {
		return &tcpproxy.DialProxy{
			Addr:                 h.Value,
			ProxyProtocolVersion: h.ProxyProtocolVersion,
		}, hostname
	}
	// then wildcard match
	split := strings.SplitAfterN(hostname, ".", 2)
	if len(split) > 0 {
		split[0] = "*"
		hostname = strings.Join(split, ".")
		if h, ok := self[hostname]; ok {
			return &tcpproxy.DialProxy{
				Addr:                 h.Value,
				ProxyProtocolVersion: h.ProxyProtocolVersion,
			}, hostname
		}
	}
	// fallback to default
	if config.Default != "" {
		return tcpproxy.To(config.Default), hostname
	} else {
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
		var ip string
		for _, h := range config.Tls {
			ip = h.Value
			_, _, err := net.SplitHostPort(ip)
			if err == nil {
				if h.Proxied {
					h.ProxyProtocolVersion = 1 // use builtin ppv1 for now
				} else {
					h.ProxyProtocolVersion = 0
				}
				hostMap[strings.ToLower(h.Name)] = h
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
	//http.HandleFunc("/status", PrintStatus)
	//go http.ListenAndServe("localhost:6060", nil)

	if bind, err := loadConfig(cfgpath); err != nil {
		glog.Fatalln(err)
	} else {
		p.AddCustomRoute(bind, &hostMap)
	}
	glog.Infoln("Sniproxy (google tcpproxy version) started")

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
		go p.Run()

		daemon.ServeSignals()
	}
}
