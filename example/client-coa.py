#!/usr/bin/env python3
#
# Copyright 6WIND, 2017
#

import sys
from os import path

from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode
from pyrad.server import Server, RemoteHost


def print_attributes(packet):
    print('Attributes')
    for key, value in packet.items():
        print(f'{key}: {value}')


class FakeCoA(Server):
    def HandleCoaPacket(self, packet):
        '''Accounting packet handler.
        Function that is called when a valid
        accounting packet has been received.

        :param packet: packet to process
        :type  packet: Packet class instance
        '''
        print('Received a coa request %d' % packet.code)
        print_attributes(packet)

        reply = self.CreateReplyPacket(packet)
        # try ACK or NACK
        # reply.code = PacketCode.CoANAK
        reply.code = PacketCode.CoAACK
        self.SendReplyPacket(packet.fd, reply)

    def HandleDisconnectPacket(self, packet):
        print('Received a disconnect request %d' % packet.code)
        print_attributes(packet)

        reply = self.CreateReplyPacket(packet)
        # try ACK or NACK
        # reply.code = PacketCode.DisconnectNAK
        reply.code = PacketCode.DisconnectACK
        self.SendReplyPacket(packet.fd, reply)


def main(path_to_dictionary, coa_port):
    # create server/coa only and read dictionary
    # bind and listen only on 127.0.0.1:argv[1]
    coa = FakeCoA(
        addresses=['127.0.0.1'],
        dict=Dictionary(path_to_dictionary),
        coaport=coa_port,
        auth_enabled=False,
        acct_enabled=False,
        coa_enabled=True)

    # add peers (address, secret, name)
    coa.hosts['127.0.0.1'] = RemoteHost(
        '127.0.0.1',
        b'Kah3choteereethiejeimaeziecumi',
        'localhost')

    # start
    coa.Run()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: client-coa.py {portnumber}')
        sys.exit(1)

    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')
    main(dictionary, int(sys.argv[1]))
