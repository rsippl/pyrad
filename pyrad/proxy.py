# A RADIUS proxy as defined in RFC 2138

import select
import socket

from pyrad.packet import PacketCode
from pyrad.server import Server
from pyrad.server import ServerPacketError


class Proxy(Server):
    """Base class for RADIUS proxies.
    This class extends tha RADIUS server class with the capability to
    handle communication with other RADIUS servers as well.

    :ivar _proxyfd: network socket used to communicate with other servers
    :type _proxyfd: socket class instance
    """

    def _prepare_sockets(self):
        Server._prepare_sockets(self)
        self._proxyfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._fdmap[self._proxyfd.fileno()] = self._proxyfd
        self._poll.register(
            self._proxyfd.fileno(),
            (select.POLLIN | select.POLLPRI | select.POLLERR))

    def _handle_proxy_packet(self, pkt):
        """Process a packet received on the reply socket.
        If this packet should be dropped instead of processed a
        :obj:`ServerPacketError` exception should be raised. The main loop
        will drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        if pkt.source[0] not in self.hosts:
            raise ServerPacketError('Received packet from unknown host')
        pkt.secret = self.hosts[pkt.source[0]].secret

        if pkt.code not in [PacketCode.ACCESS_ACCEPT, PacketCode.ACCESS_REJECT,
                            PacketCode.ACCOUNTING_RESPONSE]:
            raise ServerPacketError('Received non-response on proxy socket')

    def _process_input(self, fd):
        """Process available data.
        If this packet should be dropped instead of processed a
        `ServerPacketError` exception should be raised. The main loop
        will drop the packet and log the reason.

        This function calls either :obj:`handle_auth_packet`,
        :obj:`handle_acct_packet` or :obj:`_handle_proxy_packet` depending on
        which socket is being processed.

        :param  fd: socket to read packet from
        :type   fd: socket class instance
        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        if fd.fileno() == self._proxyfd.fileno():
            pkt = self._grab_packet(
                lambda data, s=self: s.create_packet(packet=data), fd)
            self._handle_proxy_packet(pkt)
        else:
            Server._process_input(self, fd)
