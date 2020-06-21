#!/usr/bin/env python3
import logging

from os import path

from pyrad.packet import PacketCode

from pyrad import server
from pyrad.dictionary import Dictionary

logging.basicConfig(filename='pyrad.log', level='DEBUG',
                    format='%(asctime)s [%(levelname)-8s] %(message)s')


def print_attributes(packet):
    print('Attributes')
    for key, value in packet.items():
        print(f'{key}: {value}')


class FakeServer(server.Server):
    def HandleAuthPacket(self, packet):
        print('Received an authentication request')
        print_attributes(packet)

        reply = self.CreateReplyPacket(packet, **{
            'Service-Type': 'Framed-User',
            'Framed-IP-Address': '192.168.0.1',
            'Framed-IPv6-Prefix': 'fc66::/64'
        })

        reply.code = PacketCode.AccessAccept
        self.SendReplyPacket(packet.fd, reply)

    def HandleAcctPacket(self, packet):
        print('Received an accounting request')
        print_attributes(packet)

        reply = self.CreateReplyPacket(packet)
        self.SendReplyPacket(packet.fd, reply)

    def HandleCoaPacket(self, packet):
        print('Received an coa request')
        print_attributes(packet)

        reply = self.CreateReplyPacket(packet)
        self.SendReplyPacket(packet.fd, reply)

    def HandleDisconnectPacket(self, packet):
        print('Received an disconnect request')
        print_attributes(packet)

        reply = self.CreateReplyPacket(packet)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(packet.fd, reply)


def main(path_to_dictionary):
    # create server and read dictionary
    srv = FakeServer(dict=Dictionary(path_to_dictionary),
                     coa_enabled=True)

    # add clients (address, secret, name)
    srv.hosts['127.0.0.1'] = server.RemoteHost(
            '127.0.0.1',
            b'Kah3choteereethiejeimaeziecumi',
            'localhost')
    srv.BindToAddress('0.0.0.0')

    # start server
    srv.Run()


if __name__ == '__main__':
    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')
    main(dictionary)
