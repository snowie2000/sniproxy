module sniproxy

go 1.16

replace github.com/google/tcpproxy => ./deps/google/tcpproxy

require (
	github.com/golang/glog v1.0.0
	github.com/google/tcpproxy v0.0.0-00010101000000-000000000000
	github.com/sevlyar/go-daemon v0.1.5
)

require (
	github.com/deckarep/golang-set v1.8.0
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/pires/go-proxyproto v0.6.2 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
)
