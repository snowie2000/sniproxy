#!/usr/bin/env python
# coding:utf-8
# based on http://tools.ietf.org/html/rfc4366#section-3.1
# based on http://en.wikipedia.org/wiki/Server_Name_Indication
# based on http://www.infoq.com/cn/articles/HTTPS-Connection-Jeff-Moser
# based on http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html
# based on http://nongnu.askapache.com/sniproxy/sniproxy.tgz
# contributor:
#      Phus Lu        <phus.lu@gmail.com>

import gevent.monkey
gevent.monkey.patch_all()
import gevent
import gevent.server

import io
import logging
import socket
import struct

def extract_server_name(packet):
    if packet.startswith(b'\x16\x03'):
        stream = io.BytesIO(packet)
        stream.read(0x2b)
        session_id_length = ord(stream.read(1))
        stream.read(session_id_length)
        cipher_suites_length, = struct.unpack('>h', stream.read(2))
        stream.read(cipher_suites_length+2)
        extensions_length, = struct.unpack('>h', stream.read(2))
        extensions = {}
        while True:
            data = stream.read(2)
            if not data:
                break
            etype, = struct.unpack('>h', data)
            elen, = struct.unpack('>h', stream.read(2))
            edata = stream.read(elen)
            if etype == 0:
                server_name = edata[5:].decode()
                return server_name


def io_copy(dest, src, timeout=60, bufsize=8192):
    """forward socket"""
    try:
        while True:
            data = src.recv(bufsize)
            if not data:
                break
            src.sendall(data)
    except Exception as ex:
        logging.exception('io_copy error: %r', ex)
    finally:
        for sock in (dest, src):
            try:
                sock.close()
            except Exception:
                pass


class SNIProxy(gevent.server.StreamServer):
    """Echo server class"""

    def __init__(self, *args, **kwargs):
        gevent.server.StreamServer.__init__(self, *args, **kwargs)

    def handle(self, sock, addr):
        peername = writer.get_extra_info('peername')
        logging.info('Accepted connection from {}'.format(peername))
        data = sock.recv(1500)
        server_name = extract_server_name(data)
        logging.info('Attmpt open_connection to {}'.format(server_name))
        remote = socket.create_connection((server_name, 443))
        remote.sendall(data)
        gevent.spawn(forward_socket, sock, remote)
        gevent.spawn(forward_socket, remote, sock)



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    SNIProxy(('127.0.0.1', 443)).serve_forever()
