from pyrad import packet


class Host:
    """Generic RADIUS capable host.

    :ivar     dict: RADIUS dictionary
    :type     dict: pyrad.dictionary.Dictionary
    :ivar authport: port to listen on for authentication packets
    :type authport: integer
    :ivar acctport: port to listen on for accounting packets
    :type acctport: integer
    """

    def __init__(self, authport=1812, acctport=1813, coaport=3799, dict=None):
        """Constructor

        :param authport: port to listen on for authentication packets
        :type  authport: integer
        :param acctport: port to listen on for accounting packets
        :type  acctport: integer
        :param coaport: port to listen on for CoA packets
        :type  coaport: integer
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        """
        self.dict = dict
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport

    def create_packet(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS authentication
        packet which can be used to communicate with the RADIUS server
        this client talks to. This is initializing the new packet with
        the dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return packet.Packet(dict=self.dict, **args)

    def create_auth_packet(self, **args):
        """Create a new authentication RADIUS packet.
        This utility function creates a new RADIUS authentication
        packet which can be used to communicate with the RADIUS server
        this client talks to. This is initializing the new packet with
        the dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AuthPacket
        """
        return packet.AuthPacket(dict=self.dict, **args)

    def create_acct_packet(self, **args):
        """Create a new accounting RADIUS packet.
        This utility function creates a new accouting RADIUS packet
        which can be used to communicate with the RADIUS server this
        client talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AcctPacket
        """
        return packet.AcctPacket(dict=self.dict, **args)

    def create_coa_packet(self, **args):
        """Create a new CoA RADIUS packet.
        This utility function creates a new CoA RADIUS packet
        which can be used to communicate with the RADIUS server this
        client talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.CoAPacket
        """
        return packet.CoAPacket(dict=self.dict, **args)

    def send_packet(self, fd, pkt):
        """Send a packet.

        :param fd: socket to send packet with
        :type  fd: socket class instance
        :param pkt: packet to send
        :type  pkt: Packet class instance
        """
        fd.sendto(pkt.Packet(), pkt.source)

    def send_reply_packet(self, fd, pkt):
        """Send a packet.

        :param fd: socket to send packet with
        :type  fd: socket class instance
        :param pkt: packet to send
        :type  pkt: Packet class instance
        """
        fd.sendto(pkt.create_raw_reply(), pkt.source)
