__docformat__ = "epytext en"

import hashlib
import select
import socket
import struct
import time

from pyrad import host
from pyrad import packet
from pyrad.packet import PacketCode

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_TYPE_IDENTITY = 1


class Timeout(Exception):
    """Simple exception class which is raised when a timeout occurs
    while waiting for a RADIUS server to respond."""


class Client(host.Host):
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.

    :ivar retries: number of times to retry sending a RADIUS request
    :type retries: integer
    :ivar timeout: number of seconds to wait for an answer
    :type timeout: float
    """

    def __init__(self, server, authport=1812, acctport=1813,
                 coaport=3799, secret=b'', dict=None, retries=3,
                 timeout=5):

        """Constructor.

        :param   server: hostname or IP address of RADIUS server
        :type    server: string
        :param authport: port to use for authentication packets
        :type  authport: integer
        :param acctport: port to use for accounting packets
        :type  acctport: integer
        :param coaport: port to use for CoA packets
        :type  coaport: integer
        :param   secret: RADIUS secret
        :type    secret: bytes
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        """
        host.Host.__init__(self, authport, acctport, coaport, dict)

        self.server = server
        self.secret = secret
        self._socket = None
        self.retries = retries
        self.timeout = timeout
        self._poll = select.poll()

    def bind(self, addr):
        """Bind socket to an address.
        Binding the socket used for communicating to an address can be
        usefull when working on a machine with multiple addresses.

        :param addr: network address (hostname or IP) and port to bind to
        :type  addr: host,port tuple
        """
        self._close_socket()
        self._open_socket()
        self._socket.bind(addr)

    def _open_socket(self):
        try:
            family = socket.getaddrinfo(self.server, 'www')[0][0]
        except:
            family = socket.AF_INET
        if not self._socket:
            self._socket = socket.socket(family,
                                         socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_REUSEADDR, 1)
            self._poll.register(self._socket, select.POLLIN)

    def _close_socket(self):
        if self._socket:
            self._poll.unregister(self._socket)
            self._socket.close()
            self._socket = None

    def create_auth_packet(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AuthPacket
        """
        return host.Host.create_auth_packet(self, secret=self.secret, **args)

    def create_acct_packet(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return host.Host.create_acct_packet(self, secret=self.secret, **args)

    def create_coa_packet(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return host.Host.create_coa_packet(self, secret=self.secret, **args)

    def _send_packet(self, pkt, port):
        """Send a packet to a RADIUS server.

        :param pkt:  the packet to send
        :type pkt:   pyrad.packet.Packet
        :param port: UDP port to send packet to
        :type port:  integer
        :return:     the reply packet received
        :rtype:      pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        self._open_socket()

        for attempt in range(self.retries):
            if attempt and pkt.code == PacketCode.ACCOUNTING_REQUEST:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = \
                        pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout

            now = time.time()
            waitto = now + self.timeout

            self._socket.sendto(pkt.create_raw_request(), (self.server, port))

            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)

                if ready:
                    rawreply = self._socket.recv(4096)
                else:
                    now = time.time()
                    continue

                try:
                    reply = pkt.create_reply(packet=rawreply)
                    if pkt.verify_reply(reply, rawreply):
                        return reply
                except PacketCode.PacketError:
                    pass

                now = time.time()

        raise Timeout

    def send_packet(self, pkt):
        """Send a packet to a RADIUS server.

        :param pkt: the packet to send
        :type pkt:  pyrad.packet.Packet
        :return:    the reply packet received
        :rtype:     pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        if isinstance(pkt, packet.AuthPacket):
            if pkt.auth_type == 'eap-md5':
                # Creating EAP-Identity
                password = pkt[2][0] if 2 in pkt else pkt[1][0]
                pkt[79] = [struct.pack('!BBHB%ds' % len(password),
                                       EAP_CODE_RESPONSE,
                                       packet.current_id,
                                       len(password) + 5,
                                       EAP_TYPE_IDENTITY,
                                       password)]
            reply = self._send_packet(pkt, self.authport)
            if (
                    reply
                    and reply.code == PacketCode.ACCESS_CHALLENGE
                    and pkt.auth_type == 'eap-md5'
            ):
                # Got an Access-Challenge
                eap_code, eap_id, eap_size, eap_type, eap_md5 = struct.unpack(
                    '!BBHB%ds' % (len(reply[79][0]) - 5), reply[79][0]
                )
                # Sending back an EAP-Type-MD5-Challenge
                # Thank god for http://www.secdev.org/python/eapy.py
                client_pw = pkt[2][0] if 2 in pkt else pkt[1][0]
                md5_challenge = hashlib.md5(
                    struct.pack('!B', eap_id) + client_pw + eap_md5[1:]
                ).digest()
                pkt[79] = [
                    struct.pack('!BBHBB', 2, eap_id, len(md5_challenge) + 6,
                                4, len(md5_challenge)) + md5_challenge
                ]
                # Copy over Challenge-State
                pkt[24] = reply[24]
                reply = self._send_packet(pkt, self.authport)
            return reply
        elif isinstance(pkt, packet.CoAPacket):
            return self._send_packet(pkt, self.coaport)
        else:
            return self._send_packet(pkt, self.acctport)
