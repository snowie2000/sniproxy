#!/usr/bin/env python
# coding:utf-8
# based on http://tools.ietf.org/html/rfc4366#section-3.1
# based on http://www.infoq.com/cn/articles/HTTPS-Connection-Jeff-Moser
# based on http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html
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

import struct


class ClientHello(object):
    """Client Hello Message"""
    def __init__(self, fp):
        self.fp = fp
        self.parse_headers()

    def parse_header(self):
        fp = self.fp
        self.tls_header = fp.read(5)
        self.handshake_header = fp.read(4)
        self.version_number = fp.read(2)
        self.timestamp = fp.read(4)
        self.random = fp.read(28)
        self.session_id = fp.read(1)
        self.cipher_suites_length, = struct.unpack('>H', fp.read(2))
        self.cipher_suites = fp.read(2 * self.cipher_suites_length)
        self.server_name_type = fp.read(7)
        self.server_name_length, = struct.unpack('>H', fp.read(2))
        self.server_name = fp.read(self.server_name_length)


def SNIProxyHandler(object):
    """SNI Proxy Handler"""
    def __init__(self, sock, address):
        self.sock = sock
        self.address = address

    def process_request(self):
        pass


def main():
    server = gevent.server.StreamServer(('', 443), SNIProxyHandler)
    server.server_forever()

if __name__ == '__main__':
    main()
