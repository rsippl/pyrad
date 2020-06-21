import os
import unittest

from collections import OrderedDict
from pyrad import packet
from pyrad.client import Client
from pyrad.tests import home
from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode

import hashlib
md5_constructor = hashlib.md5


class UtilityTests(unittest.TestCase):
    def testGenerateID(self):
        id = packet.CreateID()
        self.assertTrue(isinstance(id, int))
        newid = packet.CreateID()
        self.assertNotEqual(id, newid)


class PacketConstructionTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'simple'))

    def testBasicConstructor(self):
        pkt = self.klass()
        self.assertTrue(isinstance(pkt.code, int))
        self.assertTrue(isinstance(pkt.id, int))
        self.assertTrue(isinstance(pkt.secret, bytes))

    def testNamedConstructor(self):
        pkt = self.klass(code=26, id=38, secret=b'secret',
                         authenticator=b'authenticator',
                         dict='fakedict')
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, b'secret')
        self.assertEqual(pkt.authenticator, b'authenticator')
        self.assertEqual(pkt.dict, 'fakedict')

    def testConstructWithDictionary(self):
        pkt = self.klass(dict=self.dict)
        self.assertTrue(pkt.dict is self.dict)

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        self.assertFalse(getattr(pkt, 'fd', None) is marker)

    def testSecretMustBeBytestring(self):
        self.assertRaises(TypeError, self.klass, secret='secret')

    def testConstructorWithAttributes(self):
        pkt = self.klass(**{'Test-String': 'this works', 'dict': self.dict})
        self.assertEqual(pkt['Test-String'], ['this works'])

    def testConstructorWithTlvAttribute(self):
        pkt = self.klass(**{
            'Test-Tlv-Str': 'this works',
            'Test-Tlv-Int': 10,
            'dict': self.dict
        })
        self.assertEqual(
            pkt['Test-Tlv'],
            {'Test-Tlv-Str': ['this works'], 'Test-Tlv-Int': [10]}
        )


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.Packet(
            id=0, secret=b'secret',
            authenticator=b'01234567890ABCDEF', dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer': 10})
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testAttributeAccess(self):
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet['Test-Integer'], [10])
        self.assertEqual(self.packet[3], [b'\x00\x00\x00\x0a'])

        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet['Test-String'], ['dummy'])
        self.assertEqual(self.packet[1], [b'dummy'])

    def testAttributeValueAccess(self):
        self.packet['Test-Integer'] = 'Three'
        self.assertEqual(self.packet['Test-Integer'], ['Three'])
        self.assertEqual(self.packet[3], [b'\x00\x00\x00\x03'])

    def testVendorAttributeAccess(self):
        self.packet['Simplon-Number'] = 10
        self.assertEqual(self.packet['Simplon-Number'], [10])
        self.assertEqual(self.packet[(16, 1)], [b'\x00\x00\x00\x0a'])

        self.packet['Simplon-Number'] = 'Four'
        self.assertEqual(self.packet['Simplon-Number'], ['Four'])
        self.assertEqual(self.packet[(16, 1)], [b'\x00\x00\x00\x04'])

    def testRawAttributeAccess(self):
        marker = [b'']
        self.packet[1] = marker
        self.assertTrue(self.packet[1] is marker)
        self.packet[(16, 1)] = marker
        self.assertTrue(self.packet[(16, 1)] is marker)

    def testHasKey(self):
        self.assertEqual('Test-String' in self.packet, False)
        self.packet['Test-String'] = 'dummy'
        self.assertEqual('Test-String' in self.packet, True)
        self.assertEqual(1 in self.packet, True)

    def testHasKeyWithUnknownKey(self):
        self.assertEqual('Unknown-Attribute' in self.packet, False)

    def testDelItem(self):
        self.packet['Test-String'] = 'dummy'
        del self.packet['Test-String']
        self.assertEqual('Test-String' in self.packet, False)
        self.packet['Test-String'] = 'dummy'
        del self.packet[1]
        self.assertEqual('Test-String' in self.packet, False)

    def testKeys(self):
        self.assertEqual(self.packet.keys(), [])
        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet.keys(), ['Test-String'])
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet.keys(), ['Test-String', 'Test-Integer'])
        OrderedDict.__setitem__(self.packet, 12345, None)
        self.assertEqual(self.packet.keys(),
                         ['Test-String', 'Test-Integer', 12345])

    def testCreateAuthenticator(self):
        a = packet.Packet.CreateAuthenticator()
        self.assertTrue(isinstance(a, bytes))
        self.assertEqual(len(a), 16)

        b = packet.Packet.CreateAuthenticator()
        self.assertNotEqual(a, b)

    def testGenerateID(self):
        id = self.packet.CreateID()
        self.assertTrue(isinstance(id, int))
        newid = self.packet.CreateID()
        self.assertNotEqual(id, newid)

    def testReplyPacket(self):
        reply = self.packet.ReplyPacket()
        self.assertEqual(
                reply,
                (b'\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
                 b'\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7'))

    def testVerifyReply(self):
        reply = self.packet.CreateReply()
        self.assertEqual(self.packet.VerifyReply(reply), True)

        reply.id += 1
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.id = self.packet.id

        reply.secret = b'different'
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.secret = self.packet.secret

        reply.authenticator = b'X' * 16
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.authenticator = self.packet.authenticator

    def testPktEncodeAttribute(self):
        encode = self.packet._PktEncodeAttribute

        # Encode a normal attribute
        self.assertEqual(
                encode(1, b'value'),
                b'\x01\x07value')
        # Encode a vendor attribute
        self.assertEqual(
                encode((1, 2), b'value'),
                b'\x1a\x0d\x00\x00\x00\x01\x02\x07value')

    def testPktEncodeTlvAttribute(self):
        encode = self.packet._PktEncodeTlv

        # Encode a normal tlv attribute
        self.assertEqual(
                encode(4, {1: [b'value'], 2: [b'\x00\x00\x00\x02']}),
                b'\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02')

        # Encode a normal tlv attribute with several sub attribute instances
        self.assertEqual(
                encode(4, {1: [b'value', b'other'], 2: [b'\x00\x00\x00\x02']}),
                b'\x04\x16\x01\x07value\x02\x06\x00\x00\x00\x02\x01\x07other')
        # Encode a vendor tlv attribute
        self.assertEqual(
                encode((16, 3), {1: [b'value'], 2: [b'\x00\x00\x00\x02']}),
                b'\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02')

    def testPktEncodeLongTlvAttribute(self):
        encode = self.packet._PktEncodeTlv

        long_str = b'a' * 245
        # Encode a long tlv attribute - check it is split between AVPs
        self.assertEqual(
                encode(4, {1: [b'value', long_str], 2: [b'\x00\x00\x00\x02']}),
                b'\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02\x04\xf9\x01\xf7' + long_str)

        # Encode a long vendor tlv attribute
        first_avp = b'\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02'
        second_avp = b'\x1a\xff\x00\x00\x00\x10\x03\xf9\x01\xf7' + long_str
        self.assertEqual(
                encode((16, 3), {1: [b'value', long_str], 2: [b'\x00\x00\x00\x02']}),
                first_avp + second_avp)

    def testPktEncodeAttributes(self):
        self.packet[1] = [b'value']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x01\x07value')

        self.packet.clear()
        self.packet[(16, 2)] = [b'value']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x1a\x0d\x00\x00\x00\x10\x02\x07value')

        self.packet.clear()
        self.packet[1] = [b'one', b'two', b'three']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x01\x05one\x01\x05two\x01\x07three')

        self.packet.clear()
        self.packet[1] = [b'value']
        self.packet[(16, 2)] = [b'value']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x01\x07value\x1a\x0d\x00\x00\x00\x10\x02\x07value')

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._PktDecodeVendorAttribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(b''), [(26, b'')])
        self.assertEqual(decode(b'12345'), [(26, b'12345')])

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(decode(b'\x00\x00\x00\x01\x02\x06value'),
                         [(26, b'\x00\x00\x00\x01\x02\x06value')])

        # Proper RFC2865 recommended form
        self.assertEqual(decode(b'\x00\x00\x00\x10\x02\x07value'),
                         [((16, 2), b'value')])

    def testPktDecodeTlvAttribute(self):
        decode = self.packet._PktDecodeTlvAttribute

        decode(4, b'\x01\x07value')
        self.assertEqual(self.packet[4], {1: [b'value']})

        # add another instance of the same sub attribute
        decode(4, b'\x01\x07other')
        self.assertEqual(self.packet[4], {1: [b'value', b'other']})

        # add a different sub attribute
        decode(4, b'\x02\x07\x00\x00\x00\x01')
        self.assertEqual(self.packet[4], {
            1: [b'value', b'other'],
            2: [b'\x00\x00\x00\x01']
        })

    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.DecodePacket(b'')
        except packet.PacketError as e:
            self.assertTrue('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.DecodePacket(b'\x00\x00\x00\x001234567890123456')
        except packet.PacketError as e:
            self.assertTrue('invalid length' in str(e))
        else:
            self.fail()

    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.DecodePacket(b'\x00\x00\x24\x00' + (0x2400 - 4) * b'X')
        except packet.PacketError as e:
            self.assertTrue('too long' in str(e))
        else:
            self.fail()

    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.DecodePacket(
                    b'\x01\x02\x00\x151234567890123456\x00')
        except packet.PacketError as e:
            self.assertTrue('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithoutAttributes(self):
        self.packet.DecodePacket(b'\x01\x02\x00\x141234567890123456')
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, b'1234567890123456')
        self.assertEqual(self.packet.keys(), [])

    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.DecodePacket(
                b'\x01\x02\x00\x161234567890123456\x00\x01')
        except packet.PacketError as e:
            self.assertTrue('too small' in str(e))
        else:
            self.fail()

    def testDecodePacketWithEmptyAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x161234567890123456\x01\x02')
        self.assertEqual(self.packet[1], [b''])

    def testDecodePacketWithAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1b1234567890123456\x01\x07value')
        self.assertEqual(self.packet[1], [b'value'])

    def testDecodePacketWithTlvAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value')
        self.assertEqual(self.packet[4], {1: [b'value']})

    def testDecodePacketWithVendorTlvAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x231234567890123456\x1a\x0f\x00\x00\x00\x10\x03\x09\x01\x07value')
        self.assertEqual(self.packet[(16, 3)], {1: [b'value']})

    def testDecodePacketWithTlvAttributeWith2SubAttributes(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x231234567890123456\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x09')
        self.assertEqual(self.packet[4], {1: [b'value'], 2: [b'\x00\x00\x00\x09']})

    def testDecodePacketWithSplitTlvAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x251234567890123456\x04\x09\x01\x07value\x04\x09\x02\x06\x00\x00\x00\x09')
        self.assertEqual(self.packet[4], {1: [b'value'], 2: [b'\x00\x00\x00\x09']})

    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two')
        self.assertEqual(self.packet[1], [b'one', b'two'])

    def testDecodePacketWithTwoAttributes(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two')
        self.assertEqual(self.packet[1], [b'one', b'two'])

    def testDecodePacketWithVendorAttribute(self):
        self.packet.DecodePacket(
                b'\x01\x02\x00\x1b1234567890123456\x1a\x07value')
        self.assertEqual(self.packet[26], [b'value'])

    def testEncodeKeyValues(self):
        self.assertEqual(self.packet._EncodeKeyValues(1, '1234'), (1, '1234'))

    def testEncodeKey(self):
        self.assertEqual(self.packet._EncodeKey(1), 1)

    def testAddAttribute(self):
        self.packet.AddAttribute('Test-String', '1')
        self.assertEqual(self.packet['Test-String'], ['1'])
        self.packet.AddAttribute('Test-String', '1')
        self.assertEqual(self.packet['Test-String'], ['1', '1'])
        self.packet.AddAttribute('Test-String', ['2', '3'])
        self.assertEqual(self.packet['Test-String'], ['1', '1', '2', '3'])


class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, PacketCode.AccessRequest)


class AuthPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(
                id=0, secret=b'secret',
                authenticator=b'01234567890ABCDEF', dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer': 10})
        self.assertEqual(reply.code, PacketCode.AccessAccept)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
                         b'\x01\x00\x00\x1401234567890ABCDE')

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.authenticator is not None)

    def testRequestPacketCreatesID(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.id is not None)

    def testPwCryptEmptyPassword(self):
        self.assertEqual(self.packet.PwCrypt(''), b'')

    def testPwCryptPassword(self):
        self.assertEqual(self.packet.PwCrypt('Simplon'),
                         b'\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01')

    def testPwCryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.PwCrypt('')
        self.assertTrue(self.packet.authenticator is not None)

    def testPwDecryptEmptyPassword(self):
        self.assertEqual(self.packet.PwDecrypt(b''), '')

    def testPwDecryptPassword(self):
        self.assertEqual(
            self.packet.PwDecrypt(b'\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01'),
            'Simplon')


class AuthPacketChapTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'chap'))
        self.client = Client(server='localhost', secret=b'secret',
                             dict=self.dict)

    def testVerifyChapPasswd(self):
        chap_id = b'9'
        chap_challenge = b'987654321'
        chap_password = chap_id + md5_constructor(
                chap_id + b'test_password' + chap_challenge).digest()
        pkt = self.client.CreateAuthPacket(
            code=PacketCode.AccessChallenge,
            authenticator=b'ABCDEFG',
            User_Name='test_name',
            CHAP_Challenge=chap_challenge,
            CHAP_Password=chap_password
        )
        self.assertEqual(pkt['CHAP-Challenge'][0], chap_challenge)
        self.assertEqual(pkt['CHAP-Password'][0], chap_password)
        self.assertEqual(pkt.VerifyChapPasswd('test_password'), True)


class AuthPacketSaltTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'tunnelPassword'))
        self.packet = packet.Packet(id=0, secret=b'secret',
                                    dict=self.dict)

    def testSaltCrypt(self):
        self.packet['Tunnel-Password:1'] = 'test'
        # TODO: need to get a correct reference values
        # self.assertEqual(self.packet['Tunnel-Password'], b'')


class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, PacketCode.AccountingRequest)

    def testConstructorRawPacket(self):
        raw = (b'\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
               b'\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7')
        pkt = self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AcctPacket(
            id=0, secret=b'secret',
            authenticator=b'01234567890ABCDEF', dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer': 10})
        self.assertEqual(reply.code, PacketCode.AccountingResponse)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testVerifyAcctRequest(self):
        rawpacket = self.packet.RequestPacket()
        pkt = packet.AcctPacket(secret=b'secret', packet=rawpacket)
        self.assertEqual(pkt.VerifyAcctRequest(), True)

        pkt.secret = b'different'
        self.assertEqual(pkt.VerifyAcctRequest(), False)
        pkt.secret = b'secret'

        pkt.raw_packet = b'X' + pkt.raw_packet[1:]
        self.assertEqual(pkt.VerifyAcctRequest(), False)

    def testRequestPacket(self):
        self.assertEqual(
            self.packet.RequestPacket(),
            b'\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f')

    def testRequestPacketSetsId(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.id is not None)
