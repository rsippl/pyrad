# A RADIUS packet as defined in RFC 2138

import hmac
import secrets
import struct
from collections import OrderedDict
from enum import IntEnum
from hashlib import md5

from pyrad import encoding


class PacketCode(IntEnum):
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13
    DISCONNECT_REQUEST = 40
    DISCONNECT_ACK = 41
    DISCONNECT_NAK = 42
    COA_REQUEST = 43
    COA_ACK = 44
    COA_NAK = 45


# Use cryptographic-safe random generator as provided by the OS.
random_generator = secrets.SystemRandom()

# Current ID
current_id = random_generator.randrange(1, 255)


class PacketError(Exception):
    pass


class Packet(OrderedDict):
    """Packet acts like a standard python map to provide simple access
    to the RADIUS attributes. Since RADIUS allows for repeated
    attributes the value will always be a sequence. pyrad makes sure
    to preserve the ordering when encoding and decoding packets.

    There are two ways to use the map interface: if attribute
    names are used pyrad takes care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    Normally you will not use this class directly, but one of the
    :obj:`AuthPacket` or :obj:`AcctPacket` classes.
    """

    def __init__(self, code=0, id=None, secret=b'', authenticator=None,
                 **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  bytes
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        OrderedDict.__init__(self)
        self.code = code
        if id is not None:
            self.id = id
        else:
            self.id = create_id()
        if not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.secret = secret
        if authenticator is not None and not isinstance(authenticator, bytes):
            raise TypeError('authenticator must be a binary string')
        self.authenticator = authenticator
        self.message_authenticator = None

        if 'dict' in attributes:
            self.dict = attributes['dict']

        if 'packet' in attributes:
            self.decode_packet(attributes['packet'])

        if 'message_authenticator' in attributes:
            self.message_authenticator = attributes['message_authenticator']

        for (key, value) in attributes.items():
            if key in [
                'dict', 'fd', 'packet',
                'message_authenticator',
            ]:
                continue
            key = key.replace('_', '-')
            self.add_attribute(key, value)

    def add_message_authenticator(self):

        self.message_authenticator = True
        # Maintain a zero octets content for md5 and hmac calculation.
        self['Message-Authenticator'] = 16 * b'\00'

        if self.id is None:
            self.id = self.create_id()

        if self.authenticator is None and self.code == PacketCode.ACCESS_REQUEST:
            self.authenticator = self.create_authenticator()
            self._refresh_message_authenticator()

    def get_message_authenticator(self):
        self._refresh_message_authenticator()
        return self.message_authenticator

    def _refresh_message_authenticator(self):
        hmac_constructor = hmac.new(self.secret, digestmod=md5)

        # Maintain a zero octets content for md5 and hmac calculation.
        self['Message-Authenticator'] = 16 * b'\00'
        attr = self._pkt_encode_attributes()

        header = self._encode_header(attr)

        hmac_constructor.update(header[0:4])
        if self.code in (PacketCode.ACCOUNTING_REQUEST, PacketCode.DISCONNECT_REQUEST,
                         PacketCode.COA_REQUEST, PacketCode.ACCOUNTING_RESPONSE):
            hmac_constructor.update(16 * b'\00')
        else:
            # NOTE: self.authenticator on reply packet is initialized
            #       with request authenticator by design.
            #       For ACCESS_ACCEPT, ACCESS_REJECT and ACCESS_CHALLENGE
            #       it is needed to use original Authenticator.
            #       For ACCESS_ACCEPT, ACCESS_REJECT and ACCESS_CHALLENGE
            #       it is needed to use original Authenticator.
            if self.authenticator is None:
                raise Exception('No authenticator found')
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self['Message-Authenticator'] = hmac_constructor.digest()

    def verify_message_authenticator(self, secret=None,
                                     original_authenticator=None,
                                     original_code=None):
        """Verify packet Message-Authenticator.

        :return: False if verification failed else True
        :rtype: boolean
        """
        if self.message_authenticator is None:
            raise Exception('No Message-Authenticator AVP present')

        prev_ma = self['Message-Authenticator']
        # Set zero bytes for Message-Authenticator for md5 calculation
        if secret is None and self.secret is None:
            raise Exception('Missing secret for HMAC/MD5 verification')

        if secret:
            key = secret
        else:
            key = self.secret

        self['Message-Authenticator'] = 16 * b'\00'
        attr = self._pkt_encode_attributes()

        header = self._encode_header(attr)

        hmac_constructor = hmac.new(key, digestmod=md5)
        hmac_constructor.update(header)
        if self.code in (PacketCode.ACCOUNTING_REQUEST, PacketCode.DISCONNECT_REQUEST,
                         PacketCode.COA_REQUEST, PacketCode.ACCOUNTING_RESPONSE):
            if original_code is None or original_code != PacketCode.STATUS_SERVER:
                # TODO: Handle Status-Server response correctly.
                hmac_constructor.update(16 * b'\00')
        elif self.code in (PacketCode.ACCESS_ACCEPT,
                           PacketCode.ACCESS_CHALLENGE,
                           PacketCode.ACCESS_REJECT):
            if original_authenticator is None:
                if self.authenticator is None:
                    # NOTE: self.authenticator on reply packet is initialized
                    #       with request authenticator by design.
                    original_authenticator = self.authenticator
                else:
                    raise Exception('Missing original authenticator')

            hmac_constructor.update(original_authenticator)
        else:
            # On Access-Request and Status-Server use dynamic authenticator
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self['Message-Authenticator'] = prev_ma[0]
        return prev_ma[0] == hmac_constructor.digest()

    def _encode_header(self, attr):
        return struct.pack('!BBH', self.code, self.id, 20 + len(attr))

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return Packet(id=self.id, secret=self.secret,
                      authenticator=self.authenticator, dict=self.dict,
                      **attributes)

    def create_raw_request(self):
        raise NotImplementedError()

    @staticmethod
    def _decode_value(attr, value):
        try:
            return attr.values.get_backward(value)
        except KeyError:
            return encoding.decode_attr(attr.type, value)

    def _encode_value(self, attr, value):
        try:
            result = attr.values.get_forward(value)
        except KeyError:
            result = encoding.encode_attr(attr.type, value)

        if attr.encrypt == 2:
            # salt encrypt attribute
            result = self.salt_crypt(result)

        return result

    def _encode_key_values(self, key, values):
        if not isinstance(key, str):
            return key, values

        if not isinstance(values, (list, tuple)):
            values = [values]

        key, _, tag = key.partition(":")
        attr = self.dict.attributes[key]
        key = self._encode_key(key)
        if attr.has_tag:
            tag = '0' if tag == '' else tag
            tag = struct.pack('B', int(tag))
            if attr.type == "integer":
                return key, [tag + self._encode_value(attr, v)[1:] for v in values]
            else:
                return key, [tag + self._encode_value(attr, v) for v in values]
        else:
            return key, [self._encode_value(attr, v) for v in values]

    def _encode_key(self, key):
        if not isinstance(key, str):
            return key

        attr = self.dict.attributes[key]
        # sub attribute keys don't need vendor
        if attr.vendor and not attr.is_sub_attribute:
            return self.dict.vendors.get_forward(attr.vendor), attr.code
        else:
            return attr.code

    def _decode_key(self, key):
        """Turn a key into a string if possible"""

        try:
            return self.dict.attrindex.get_backward(key)
        except KeyError:
            pass
        return key

    def add_attribute(self, key, value):
        """Add an attribute to the packet.

        :param key:   attribute name or identification
        :type key:    string, attribute code or (vendor code, attribute code)
                      tuple
        :param value: value
        :type value:  depends on type of attribute
        """
        attr = self.dict.attributes[key.partition(':')[0]]

        (key, value) = self._encode_key_values(key, value)

        if attr.is_sub_attribute:
            tlv = self.setdefault(self._encode_key(attr.parent.name), {})
            encoded = tlv.setdefault(key, [])
        else:
            encoded = self.setdefault(key, [])

        encoded.extend(value)

    def get(self, key, failobj=None):
        try:
            res = self.__getitem__(key)
        except KeyError:
            res = failobj
        return res

    def __getitem__(self, key):
        if not isinstance(key, str):
            return OrderedDict.__getitem__(self, key)

        values = OrderedDict.__getitem__(self, self._encode_key(key))
        attr = self.dict.attributes[key]
        if attr.type == 'tlv':  # return map from sub attribute code to its values
            res = {}
            for (sub_attr_key, sub_attr_val) in values.items():
                sub_attr_name = attr.sub_attributes[sub_attr_key]
                sub_attr = self.dict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    res.setdefault(sub_attr_name, []).append(self._decode_value(sub_attr, v))
            return res
        else:
            res = []
            for v in values:
                res.append(self._decode_value(attr, v))
            return res

    def __contains__(self, key):
        try:
            return OrderedDict.__contains__(self, self._encode_key(key))
        except KeyError:
            return False

    has_key = __contains__

    def __delitem__(self, key):
        OrderedDict.__delitem__(self, self._encode_key(key))

    def __setitem__(self, key, item):
        if isinstance(key, str):
            (key, item) = self._encode_key_values(key, item)
        OrderedDict.__setitem__(self, key, item)

    def keys(self):
        return [self._decode_key(key) for key in OrderedDict.keys(self)]

    @staticmethod
    def create_authenticator():
        """Create a packet authenticator. All RADIUS packets contain a sixteen
        byte authenticator which is used to authenticate replies from the
        RADIUS server and in the password hiding algorithm. This function
        returns a suitable random string that can be used as an authenticator.

        :return: valid packet authenticator
        :rtype: binary string
        """

        return secrets.token_bytes(16)

    def create_id(self):
        """Create a packet ID.  All RADIUS requests have a ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        :return: ID number
        :rtype:  integer

        """
        return int.from_bytes(secrets.token_bytes(1), 'little')

    def create_raw_reply(self):
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        :return: raw reply packet
        :rtype:  string
        """
        if self.authenticator is None:
            raise ValueError('Authenticator not initialized')
        if self.secret is None:
            raise ValueError('Secret not initialized')

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        header = self._encode_header(attr)

        authenticator = md5(header[0:4] + self.authenticator + attr + self.secret).digest()

        return header + authenticator + attr

    def verify_reply(self, reply, rawreply=None):
        if reply.id != self.id:
            return False

        if rawreply is None:
            rawreply = reply.create_raw_reply()

        attr = reply._pkt_encode_attributes()
        #  The Authenticator field in an Accounting-Response packet is called
        #  the Response Authenticator, and contains a one-way MD5 hash
        #  calculated over a stream of octets consisting of the Accounting
        #  Response Code, Identifier, Length, the Request Authenticator field
        #  from the Accounting-Request packet being replied to, and the
        #  response attributes if any, followed by the shared secret.  The
        #  resulting 16 octet MD5 hash value is stored in the Authenticator
        # field of the Accounting-Response packet.
        hash = md5(rawreply[0:4] + self.authenticator + attr + self.secret).digest()

        if hash != rawreply[4:20]:
            return False
        return True

    def _pkt_encode_attribute(self, key, value):
        if isinstance(key, tuple):
            value = struct.pack('!L', key[0]) + \
                    self._pkt_encode_attribute(key[1], value)
            key = 26

        return struct.pack('!BB', key, (len(value) + 2)) + value

    def _pkt_encode_tlv(self, tlv_key, tlv_value):
        tlv_attr = self.dict.attributes[self._decode_key(tlv_key)]
        curr_avp = b''
        avps = []
        max_sub_attribute_len = max(map(lambda item: len(item[1]), tlv_value.items()))
        for i in range(max_sub_attribute_len):
            sub_attr_encoding = b''
            for (code, datalst) in tlv_value.items():
                if i < len(datalst):
                    sub_attr_encoding += self._pkt_encode_attribute(code, datalst[i])
            # split above 255. assuming len of one instance of all sub tlvs is lower than 255
            if (len(sub_attr_encoding) + len(curr_avp)) < 245:
                curr_avp += sub_attr_encoding
            else:
                avps.append(curr_avp)
                curr_avp = sub_attr_encoding
        avps.append(curr_avp)
        tlv_avps = []
        for avp in avps:
            value = struct.pack('!BB', tlv_attr.code, (len(avp) + 2)) + avp
            tlv_avps.append(value)
        if tlv_attr.vendor:
            vendor_avps = b''
            for avp in tlv_avps:
                vendor_avps += struct.pack(
                    '!BBL', 26, (len(avp) + 6),
                    self.dict.vendors.get_forward(tlv_attr.vendor)
                ) + avp
            return vendor_avps
        else:
            return b''.join(tlv_avps)

    def _pkt_encode_attributes(self):
        result = b''
        for (code, datalst) in self.items():
            attribute = self.dict.attributes.get(self._decode_key(code))
            if attribute and attribute.type == 'tlv':
                result += self._pkt_encode_tlv(code, datalst)
            else:
                for data in datalst:
                    result += self._pkt_encode_attribute(code, data)
        return result

    def _pkt_decode_vendor_attribute(self, data):
        # Check if this packet is long enough to be in the
        # RFC2865 recommended form
        if len(data) < 6:
            return [(26, data)]

        (vendor, atype, length) = struct.unpack('!LBB', data[:6])[0:3]
        attribute = self.dict.attributes.get(self._decode_key((vendor, atype)))
        try:
            if attribute and attribute.type == 'tlv':
                self._pkt_decode_tlv_attribute((vendor, atype), data[6:length + 4])
                tlvs = []  # tlv is added to the packet inside _pkt_decode_tlv_attribute
            else:
                tlvs = [((vendor, atype), data[6:length + 4])]
        except:
            return [(26, data)]

        sumlength = 4 + length
        while len(data) > sumlength:
            try:
                atype, length = struct.unpack('!BB', data[sumlength:sumlength + 2])[0:2]
            except:
                return [(26, data)]
            tlvs.append(((vendor, atype), data[sumlength + 2:sumlength + length]))
            sumlength += length
        return tlvs

    def _pkt_decode_tlv_attribute(self, code, data):
        sub_attributes = self.setdefault(code, {})
        loc = 0

        while loc < len(data):
            atype, length = struct.unpack('!BB', data[loc:loc + 2])[0:2]
            sub_attributes.setdefault(atype, []).append(data[loc + 2:loc + length])
            loc += length

    def decode_packet(self, packet):
        """Initialize the object from raw packet data.  Decode a packet as
        received from the network and decode it.

        :param packet: raw packet
        :type packet:  bytes"""

        try:
            (self.code, self.id, length, self.authenticator) = \
                struct.unpack('!BBH16s', packet[0:20])

        except struct.error:
            raise PacketError('Packet header is corrupt')
        if len(packet) != length:
            raise PacketError('Packet has invalid length')
        if length > 4096:
            raise PacketError(f'Packet length is too long ({length})')

        self.clear()

        packet = packet[20:]
        while packet:
            try:
                (key, attrlen) = struct.unpack('!BB', packet[0:2])
            except struct.error:
                raise PacketError('Attribute header is corrupt')

            if attrlen < 2:
                raise PacketError(f'Attribute length is too small (attrlen)')

            value = packet[2:attrlen]
            attribute = self.dict.attributes.get(self._decode_key(key))
            if key == 26:
                for (key, value) in self._pkt_decode_vendor_attribute(value):
                    self.setdefault(key, []).append(value)
            elif key == 80:
                # POST: Message Authenticator AVP is present.
                self.message_authenticator = True
                self.setdefault(key, []).append(value)
            elif attribute and attribute.type == 'tlv':
                self._pkt_decode_tlv_attribute(key, value)
            else:
                self.setdefault(key, []).append(value)

            packet = packet[attrlen:]

    def salt_crypt(self, value):
        """Salt Encryption

        :param value:    plaintext value
        :type value:     unicode string
        :return:         obfuscated version of the value
        :rtype:          binary string
        """

        if isinstance(value, str):
            value = value.encode('utf-8')

        if self.authenticator is None:
            # self.authenticator = self.create_authenticator()
            self.authenticator = 16 * b'\x00'

        random_value = 32768 + random_generator.randrange(0, 32767)
        result = struct.pack('!H', random_value)

        length = struct.pack("B", len(value))
        buf = length + value
        if len(buf) % 16 != 0:
            buf += b'\x00' * (16 - (len(buf) % 16))

        last = self.authenticator + result
        while buf:
            cur_hash = md5(self.secret + last).digest()
            for b, h in zip(buf, cur_hash):
                result += bytes([b ^ h])
            last = result[-16:]
            buf = buf[16:]

        return result


class AuthPacket(Packet):
    def __init__(self, code=PacketCode.ACCESS_REQUEST, id=None, secret=b'',
                 authenticator=None, auth_type='pap', **attributes):
        """Constructor

        :param code:   packet type code
        :type code:    integer (8bits)
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  bytes

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class

        :param packet: raw packet to decode
        :type packet:  string
        """

        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        self.auth_type = auth_type
        if 'packet' in attributes:
            self.raw_packet = attributes['packet']

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AuthPacket(PacketCode.ACCESS_ACCEPT, self.id,
                          self.secret, self.authenticator, dict=self.dict,
                          auth_type=self.auth_type, **attributes)

    def create_raw_request(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """
        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        if self.id is None:
            self.id = self.create_id()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        if self.auth_type == 'eap-md5':
            header = struct.pack(
                '!BBH16s', self.code, self.id, (20 + 18 + len(attr)), self.authenticator
            )
            digest = hmac.new(
                self.secret,
                header
                + attr
                + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), b''),
                digestmod=md5
            ).digest()
            return (
                    header
                    + attr
                    + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), digest)
            )

        header = struct.pack('!BBH16s', self.code, self.id,
                             (20 + len(attr)), self.authenticator)

        return header + attr

    def pw_decrypt(self, password):
        """Obfuscate a RADIUS password. RADIUS hides passwords in packets by
        using an algorithm based on the MD5 hash of the packet authenticator
        and RADIUS secret. This function reverses the obfuscation process.

        :param password: obfuscated form of password
        :type password:  binary string
        :return:         plaintext password
        :rtype:          unicode string
        """
        pw = self.radius_password_pseudo_hash(password).rstrip(b'\x00')

        return pw.decode('utf-8')

    def pw_crypt(self, password):
        """Obfuscate password.
        RADIUS hides passwords in packets by using an algorithm
        based on the MD5 hash of the packet authenticator and RADIUS
        secret. If no authenticator has been set before calling pw_crypt
        one is created automatically. Changing the authenticator after
        setting a password that has been encrypted using this function
        will not work.

        :param password: plaintext password
        :type password:  unicode string
        :return:         obfuscated version of the password
        :rtype:          binary string
        """
        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        if isinstance(password, str):
            password = password.encode('utf-8')

        buf = password
        if len(password) % 16 != 0:
            buf += b'\x00' * (16 - (len(password) % 16))

        return self.radius_password_pseudo_hash(buf)

    def radius_password_pseudo_hash(self, password):
        result = b''
        buf = password
        last = self.authenticator

        while buf:
            cur_hash = md5(self.secret + last).digest()
            for b, h in zip(buf, cur_hash):
                result += bytes([b ^ h])

            (last, buf) = (buf[:16], buf[16:])

        return result

    def verify_chap_passwd(self, userpwd):
        """ Verify RADIUS ChapPasswd

        :param userpwd: plaintext password
        :type userpwd:  str
        :return:        is verify ok
        :rtype:         bool
        """

        if not self.authenticator:
            self.authenticator = self.create_authenticator()

        if isinstance(userpwd, str):
            userpwd = userpwd.strip().encode('utf-8')

        chap_password = encoding.decode_octets(self.get(3)[0])
        if len(chap_password) != 17:
            return False

        chapid = chr(chap_password[0]).encode('utf-8')
        password = chap_password[1:]

        challenge = self.authenticator
        if 'CHAP-Challenge' in self:
            challenge = self['CHAP-Challenge'][0]
        return password == md5(chapid + userpwd + challenge).digest()

    def verify_auth_request(self):
        """Verify request authenticator.

        :return: True if verification failed else False
        :rtype: boolean
        """
        if self.raw_packet is None:
            raise ValueError('Packet not initialized')

        hash = md5(self.raw_packet[0:4] + 16 * b'\x00' + self.raw_packet[20:] +
                   self.secret).digest()
        return hash == self.authenticator


class AcctPacket(Packet):
    """RADIUS accounting packets. This class is a specialization
    of the generic :obj:`Packet` class for accounting packets.
    """

    def __init__(self, code=PacketCode.ACCOUNTING_REQUEST, id=None, secret=b'',
                 authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  bytes
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        if 'packet' in attributes:
            self.raw_packet = attributes['packet']

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AcctPacket(PacketCode.ACCOUNTING_RESPONSE, self.id,
                          self.secret, self.authenticator, dict=self.dict,
                          **attributes)

    def verify_acct_request(self):
        """Verify request authenticator.

        :return: False if verification failed else True
        :rtype: boolean
        """
        if self.raw_packet is None:
            raise ValueError('Packet not initialized')

        hash = md5(self.raw_packet[0:4] + 16 * b'\x00' + self.raw_packet[20:] +
                   self.secret).digest()

        return hash == self.authenticator

    def create_raw_request(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        if self.id is None:
            self.id = self.create_id()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        header = self._encode_header(attr)
        self.authenticator = md5(header[0:4] + 16 * b'\x00' + attr + self.secret).digest()

        ans = header + self.authenticator + attr

        return ans


class CoAPacket(Packet):
    """RADIUS CoA packets. This class is a specialization
    of the generic :obj:`Packet` class for CoA packets.
    """

    def __init__(self, code=PacketCode.COA_REQUEST, id=None, secret=b'',
                 authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  bytes
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        if 'packet' in attributes:
            self.raw_packet = attributes['packet']

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return CoAPacket(PacketCode.COA_ACK, self.id,
                         self.secret, self.authenticator, dict=self.dict,
                         **attributes)

    def verify_coa_request(self):
        """Verify request authenticator.

        :return: False if verification failed else True
        :rtype: boolean
        """
        if self.raw_packet is None:
            raise ValueError('Packet not initialized')

        hash = md5(self.raw_packet[0:4] + 16 * b'\x00' + self.raw_packet[20:] +
                   self.secret).digest()
        return hash == self.authenticator

    def create_raw_request(self):
        """Create a ready-to-transmit CoA request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr = self._pkt_encode_attributes()

        if self.id is None:
            self.id = self.create_id()

        header = self._encode_header(attr)
        self.authenticator = md5(header[0:4] + 16 * b'\x00' + attr + self.secret).digest()

        if self.message_authenticator:
            self._refresh_message_authenticator()
            attr = self._pkt_encode_attributes()
            self.authenticator = md5(header[0:4] + 16 * b'\x00' + attr + self.secret).digest()

        return header + self.authenticator + attr


def create_id():
    """Generate a packet ID.

    :return: packet ID
    :rtype:  8 bit integer
    """
    global current_id

    current_id = (current_id + 1) % 256
    return current_id
