#!/usr/bin/env python3

import asyncio
import logging
import traceback

from os import path

from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode
from pyrad.server_async import ServerAsync
from pyrad.server import RemoteHost

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except:
    pass

logging.basicConfig(level='DEBUG',
                    format='%(asctime)s [%(levelname)-8s] %(message)s')


def print_attributes(packet):
    print('Attributes returned by server:')
    for key in packet.keys():
        print(f'{key}: {packet[key]}')


class FakeServer(ServerAsync):
    def __init__(self, loop, dictionary):

        ServerAsync.__init__(self, loop=loop, dictionary=dictionary,
                             enable_pkt_verify=True, debug=True)

    def handle_auth_packet(self, protocol, packet, addr):
        print('Received an authentication request with id ', packet.id)
        print('Authenticator ', packet.authenticator.hex())
        print('Secret ', packet.secret)
        print_attributes(packet)

        reply = self.create_reply_packet(packet, **{
            'Service-Type': 'Framed-User',
            'Framed-IP-Address': '192.168.0.1',
            'Framed-IPv6-Prefix': 'fc66::/64'
        })

        reply.code = PacketCode.ACCESS_ACCEPT
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, packet, addr):
        print('Received an accounting request')
        print_attributes(packet)

        reply = self.create_reply_packet(packet)
        protocol.send_response(reply, addr)

    def handle_coa_packet(self, protocol, packet, addr):
        print('Received an coa request')
        print_attributes(packet)

        reply = self.create_reply_packet(packet)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, packet, addr):
        print('Received an disconnect request')
        print_attributes(packet)

        reply = self.create_reply_packet(packet)
        # COA NAK
        reply.code = 45
        protocol.send_response(reply, addr)


def main(path_to_dictionary):
    # create server and read dictionary
    loop = asyncio.get_event_loop()
    server = FakeServer(loop=loop, dictionary=Dictionary(path_to_dictionary))

    # add clients (address, secret, name)
    server.hosts['127.0.0.1'] = RemoteHost('127.0.0.1',
                                           b'Kah3choteereethiejeimaeziecumi',
                                           'localhost')

    try:
        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                server.initialize_transports(enable_auth=True,
                                             enable_acct=True,
                                             enable_coa=True)))

        try:
            # start server
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    except Exception as exc:
        print('Error: ', exc)
        traceback.print_exc()

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    loop.close()


if __name__ == '__main__':
    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')
    main(dictionary)
