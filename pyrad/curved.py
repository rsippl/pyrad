"""Twisted integration code
"""

__docformat__ = 'epytext en'

# TODO rewrite using asyncio

import sys

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log

from pyrad import dictionary
from pyrad import host
from pyrad import packet
from pyrad.packet import PacketCode


class PacketError(Exception):
    """Exception class for bogus packets

    PacketError exceptions are only used inside the Server class to
    abort processing of a packet.
    """


class RADIUS(host.Host, protocol.DatagramProtocol):
    def __init__(self, hosts={}, dict=dictionary.Dictionary()):
        host.Host.__init__(self, dict=dict)
        self.hosts = hosts

    def process_packet(self, pkt):
        pass

    def create_packet(self, **kwargs):
        raise NotImplementedError('Attempted to use a pure base class')

    def datagramReceived(self, datagram, source):
        host, port = source
        try:
            pkt = self.create_packet(packet=datagram)
        except packet.PacketError as err:
            log.msg('Dropping invalid packet: ' + str(err))
            return

        if host not in self.hosts:
            log.msg('Dropping packet from unknown host ' + host)
            return

        pkt.source = (host, port)
        try:
            self.process_packet(pkt)
        except PacketError as err:
            log.msg('Dropping packet from %s: %s' % (host, str(err)))


class RADIUSAccess(RADIUS):
    def create_packet(self, **kwargs):
        self.create_auth_packet(**kwargs)

    def process_packet(self, pkt):
        if pkt.code != PacketCode.ACCESS_REQUEST:
            raise PacketError(
                'non-ACCESS_REQUEST packet on authentication socket')


class RADIUSAccounting(RADIUS):
    def create_packet(self, **kwargs):
        self.create_acct_packet(**kwargs)

    def process_packet(self, pkt):
        if pkt.code != PacketCode.ACCOUNTING_REQUEST:
            raise PacketError(
                'non-ACCOUNTING_REQUEST packet on authentication socket')


if __name__ == '__main__':
    log.startLogging(sys.stdout, 0)
    reactor.listenUDP(1812, RADIUSAccess())
    reactor.listenUDP(1813, RADIUSAccounting())
    reactor.run()
