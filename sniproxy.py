#!/usr/bin/env python
# coding:utf-8
# based on http://tools.ietf.org/html/rfc4366#section-3.1
# based on http://en.wikipedia.org/wiki/Server_Name_Indication
# based on http://www.infoq.com/cn/articles/HTTPS-Connection-Jeff-Moser
# based on http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html
# based on http://nongnu.askapache.com/sniproxy/sniproxy.tgz
# contributor:
#      Phus Lu        <phus.lu@gmail.com>

import asyncio
import io
import logging
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


class SNIProxy(object):
    """Echo server class"""

    def __init__(self, host, port, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        self._port = port
        self._server = asyncio.start_server(self.handle_connection, port=self._port)

    def start(self, and_loop=True):
        self._server = self._loop.run_until_complete(self._server)
        logging.info('Listening established on {0}'.format(self._server.sockets[0].getsockname()))
        if and_loop:
            self._loop.run_forever()

    def stop(self, and_loop=True):
        self._server.close()
        if and_loop:
            self._loop.close()

    @asyncio.coroutine
    def io_copy(self, reader, writer):
        while True:
            data = yield from reader.read(8192)
            if not data:
                break
            writer.write(data)
        writer.close()

    @asyncio.coroutine
    def handle_connection(self, reader, writer):
        peername = writer.get_extra_info('peername')
        logging.info('Accepted connection from {}'.format(peername))
        data = yield from reader.read(1024)
        server_name = extract_server_name(data)
        logging.info('Attmpt open_connection to {}'.format(server_name))
        remote_reader, remote_writer = yield from asyncio.open_connection(server_name, self._port)
        remote_writer.write(data)
        asyncio.async(self.io_copy(reader, remote_writer))
        yield from self.io_copy(remote_reader, writer)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = SNIProxy('127.0.0.1', 443)
    try:
        server.start()
    except KeyboardInterrupt:
        pass # Press Ctrl+C to stop
    finally:
        server.stop()

