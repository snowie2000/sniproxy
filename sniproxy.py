#!/usr/bin/env python
# coding:utf-8
# based on http://tools.ietf.org/html/rfc4366#section-3.1
# based on http://en.wikipedia.org/wiki/Server_Name_Indication
# based on http://www.infoq.com/cn/articles/HTTPS-Connection-Jeff-Moser
# based on http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html
# based on http://nongnu.askapache.com/sniproxy/sniproxy.tgz
# contributor:
#      Phus Lu        <phus.lu@gmail.com>

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))

import gevent
import gevent.server
import gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)

import re
import socket
import errno
import select
import struct
import random
import logging


def forward_socket(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, trans=None):
    try:
        timecount = timeout
        while 1:
            timecount -= tick
            if timecount <= 0:
                break
            (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            if ins:
                for sock in ins:
                    data = sock.recv(bufsize)
                    if trans:
                        data = data.translate(trans)
                    if data:
                        if sock is remote:
                            local.sendall(data)
                            timecount = maxpong or timeout
                            if pongcallback:
                                try:
                                    #remote_addr = '%s:%s'%remote.getpeername()[:2]
                                    #logging.debug('call remote=%s pongcallback=%s', remote_addr, pongcallback)
                                    pongcallback()
                                except Exception as e:
                                    logging.warning('remote=%s pongcallback=%s failed: %s', remote, pongcallback, e)
                                finally:
                                    pongcallback = None
                        else:
                            remote.sendall(data)
                            timecount = maxping or timeout
                    else:
                        return
    except socket.error as e:
        if e[0] not in (10053, 10054, 10057, errno.EPIPE):
            raise
    finally:
        if local:
            local.close()
        if remote:
            remote.close()


class DNSUtil(object):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    blacklist = set([
                    # for ipv6
                    '1.1.1.1', '255.255.255.255',
                    # for google+
                    '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113',
                    '209.85.229.138',
                    # other ip list
                    '128.121.126.139', '159.106.121.75', '169.132.13.103', '192.67.198.6',
                    '202.106.1.2', '202.181.7.85', '203.161.230.171', '203.98.7.65',
                    '207.12.88.98', '208.56.31.43', '209.145.54.50', '209.220.30.174',
                    '209.36.73.33', '211.94.66.147', '213.169.251.35', '216.221.188.182',
                    '216.234.179.13', '243.185.187.39', '37.61.54.158', '4.36.66.178',
                    '46.82.174.68', '59.24.3.173', '64.33.88.161', '64.33.99.47',
                    '64.66.163.251', '65.104.202.252', '65.160.219.113', '66.45.252.237',
                    '72.14.205.104', '72.14.205.99', '78.16.49.15', '8.7.198.45', '93.46.8.89',
                    ])
    max_retry = 3
    max_wait = 3

    @staticmethod
    def _reply_to_iplist(data):
        assert isinstance(data, basestring)
        iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        return iplist

    @staticmethod
    def is_bad_reply(data):
        assert isinstance(data, basestring)
        iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        iplist += ['.'.join(str(ord(x)) for x in s) for s in re.findall('\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        return any(x in DNSUtil.blacklist for x in iplist)

    @staticmethod
    def _remote_resolve(dnsserver, qname, timeout=None):
        if isinstance(dnsserver, tuple):
            dnsserver, port = dnsserver
        else:
            port = 53
        for i in xrange(DNSUtil.max_retry):
            host = ''.join(chr(len(x))+x for x in qname.split('.'))
            seqid = os.urandom(2)
            data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (seqid, host)
            address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
            sock = None
            try:
                if i < DNSUtil.max_retry-1:
                    # UDP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_DGRAM)
                    sock.settimeout(timeout)
                    sock.sendto(data, (dnsserver, port))
                    for i in xrange(DNSUtil.max_wait):
                        data = sock.recv(512)
                        if data and not DNSUtil.is_bad_reply(data):
                            return data[2:]
                        else:
                            logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return poisoned udp data=%r', qname, dnsserver, data)
                else:
                    # TCP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((dnsserver, port))
                    data = struct.pack('>h', len(data)) + data
                    sock.send(data)
                    rfile = sock.makefile('r', 512)
                    data = rfile.read(2)
                    if not data:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp header data=%r', qname, dnsserver, data)
                    data = rfile.read(struct.unpack('>h', data)[0])
                    if data and not DNSUtil.is_bad_reply(data):
                        return data[2:]
                    else:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp data=%r', qname, dnsserver, data)
            except socket.error as e:
                if e[0] in (10060, 'timed out'):
                    continue
            except Exception as e:
                raise
            finally:
                if sock:
                    sock.close()

    @staticmethod
    def remote_resolve(dnsserver, qname, timeout=None):
        data = DNSUtil._remote_resolve(dnsserver, qname, timeout)
        iplist = DNSUtil._reply_to_iplist(data or '')
        return iplist

    @staticmethod
    def parse_ipv6addr(ipstr):
        """https://github.com/haypo/python-ipy"""
        items = []
        index = 0
        fill_pos = None
        while index < len(ipstr):
            text = ipstr[index:]
            if text.startswith("::"):
                if fill_pos is not None:
                    raise ValueError("%r: Invalid IPv6 address: more than one '::'" % ipstr)
                fill_pos = len(items)
                index += 2
                continue
            pos = text.find(':')
            if pos == 0:
                raise ValueError("%r: Invalid IPv6 address" % ipstr)
            if pos != -1:
                items.append(text[:pos])
                if text[pos:pos+2] == "::":
                    index += pos
                else:
                    index += pos+1

                if index == len(ipstr):
                    raise ValueError("%r: Invalid IPv6 address" % ipstr)
            else:
                items.append(text)
                break
        if items and '.' in items[-1]:
            if (fill_pos is not None) and not (fill_pos <= len(items)-1):
                raise ValueError("%r: Invalid IPv6 address: '::' after IPv4" % ipstr)
            value = parseAddress(items[-1])[0]
            items = items[:-1] + ["%04x" % (value >> 16), "%04x" % (value & 0xffff)]
        if fill_pos is not None:
            diff = 8 - len(items)
            if diff <= 0:
                raise ValueError("%r: Invalid IPv6 address: '::' is not needed" % ipstr)
            items = items[:fill_pos] + ['0']*diff + items[fill_pos:]
        if len(items) != 8:
            raise ValueError("%r: Invalid IPv6 address: should have 8 hextets" % ipstr)
        value = 0
        index = 0
        for item in items:
            try:
                item = int(item, 16)
                error = not(0 <= item <= 0xffff)
            except ValueError:
                error = True
            if error:
                raise ValueError("%r: Invalid IPv6 address: invalid hexlet %r" % (ipstr, item))
            value = (value << 16) + item
            index += 1
        return value


class DNSServer(gevent.server.DatagramServer):
    """DNS Proxy over TCP to avoid DNS poisoning"""
    dnsservers = ['8.8.8.8', '8.8.4.4']
    max_wait = 1
    max_retry = 2
    max_cache_size = 20000
    timeout = 6

    def __init__(self, *args, **kwargs):
        gevent.server.DatagramServer.__init__(self, *args, **kwargs)
        self.cache = {}

    def add_record(self, qname, ip):
        domain = ''.join(chr(len(x))+x for x in qname.split('.'))
        record = '\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        record += domain
        record += '\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\n\x00'
        if ':' in ip:
            ipint = DNSUtil.parse_ipv6addr(ip)
            record += '\x10' + struct.pack('!QQ', ipint>>64, ipint&0xFFFFFFFFFFFFFFFF)
        else:
            record += '\x04' + ''.join(chr(int(x)) for x in ip.split('.'))
        self.cache[domain] = record

    def handle(self, data, address):
        reqid = data[:2]
        domain = data[12:data.find('\x00', 12)]
        if len(self.cache) > self.max_cache_size:
            self.cache.clear()
        if domain not in self.cache:
            qname = re.sub(r'[\x01-\x29]', '.', domain[1:])
            try:
                dnsserver = random.choice(self.dnsservers)
                logging.info('DNSServer resolve domain=%r by dnsserver=%r to iplist', qname, dnsserver)
                data = DNSUtil._remote_resolve(dnsserver, qname, self.timeout)
                if not data:
                    logging.warning('DNSServer resolve domain=%r return data=%s', qname, data)
                    return
                iplist = DNSUtil._reply_to_iplist(data)
                self.cache[domain] = data
                logging.info('DNSServer resolve domain=%r return iplist=%s', qname, iplist)
            except socket.error as e:
                logging.error('DNSServer resolve domain=%r to iplist failed:%s', qname, e)
        return self.sendto(reqid + self.cache[domain], address)


class SNIProxyHandler(object):
    """SNI Proxy Handler"""

    bufsize = 1024*1024
    timeout = 300

    def __init__(self, sock, address):
        self.sock = sock
        self.address = address
        self.process_request()

    def process_request(self):
        sock = self.sock
        address = self.address
        bufsize = self.bufsize
        timeout = self.timeout

        fp = sock.makefile('rb', bufsize)
        packet = fp.read(4)
        length, = struct.unpack('>H', packet[2:4])
        packet += fp.read(length)

        server_name = ''
        try:
            # extrace SNI from ClientHello packet, quick and dirty.
            server_name = (m.group(2) for m in re.finditer('\x00\x00(.)([\\w\\.]{4,255})', packet) if ord(m.group(1)) == len(m.group(2))).next()
        except StopIteration:
            pass

        # tricky. :)
        packet += fp._rbuf.getvalue()

        if server_name:
            logging.info('%s:%d forward to %r', address[0], address[1], server_name)
            # TODO: DNS cache
            # remote_iplist = socket.gethostbyname_ex(server_name)[-1]
            remote_iplist = DNSUtil.remote_resolve('8.8.8.8', server_name, timeout=timeout)
            remote_ip = remote_iplist[0]
            remote_sock = socket.create_connection((remote_ip, 443), timeout=timeout)
            remote_sock.send(packet)
            logging.info('%s:%d connected %r, begin forward_socket', address[0], address[1], remote_ip)
            forward_socket(sock, remote_sock, timeout=timeout, bufsize=bufsize)
        else:
            logging.debug('%s:%d read_sni return server_name=%r', address[0], address[1], server_name)


def get_listen_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('8.8.8.8', 53))
    listen_ip = sock.getsockname()[0]
    sock.close()
    return listen_ip


def init_dnsmap(dns_server):
    domains = ['twitter.com', 'api.twitter.com', 'platform.twitter.com', 'mobile.twitter.com']
    listen_ip = get_listen_ip()
    for domain in domains:
        dns_server.add_record(domain, listen_ip)

def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    dns_server = DNSServer(('', 53))
    init_dnsmap(dns_server)
    logging.info('serving at %r', dns_server.address)
    dns_server.start()
    sni_server = gevent.server.StreamServer(('', 443), SNIProxyHandler)
    logging.info('serving at %r', sni_server.address)
    sni_server.serve_forever()

if __name__ == '__main__':
    main()
