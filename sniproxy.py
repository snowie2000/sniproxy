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
            server_name = (m for m in re.finditer('\x00\x00(.)([\\w\\.]{4,255})', packet) if ord(m.group(1)) == len(m.group(2))).next().group(2)
        except StopIteration:
            pass

        # tricky. :)
        packet += fp._rbuf.getvalue()

        if server_name:
            logging.info('%s:%d forward to %r', address[0], address[1], server_name)
            # TODO: DNS cache
            remote_iplist = socket.gethostbyname_ex(server_name)[-1]
            remote_ip = remote_iplist[0]
            remote_sock = socket.create_connection((remote_ip, 443), timeout=timeout)
            remote_sock.send(packet)
            logging.info('%s:%d connected %r, begin forward_socket', address[0], address[1], remote_ip)
            forward_socket(sock, remote_sock, timeout=timeout, bufsize=bufsize)
        else:
            logging.debug('%s:%d read_sni return server_name=%r', address[0], address[1], server_name)


def main():
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 443
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    server = gevent.server.StreamServer(('', port), SNIProxyHandler)
    logging.info('serving at %r', server.address)
    server.serve_forever()

if __name__ == '__main__':
    main()
