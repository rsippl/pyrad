import unittest

from pyrad.host import Host
from pyrad.packet import AcctPacket
from pyrad.packet import AuthPacket
from pyrad.packet import Packet


class ConstructionTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host = Host()
        self.assertEqual(host.authport, 1812)
        self.assertEqual(host.acctport, 1813)

    def testParameterOrder(self):
        host = Host(123, 456, 789, 101)
        self.assertEqual(host.authport, 123)
        self.assertEqual(host.acctport, 456)
        self.assertEqual(host.coaport, 789)
        self.assertEqual(host.dict, 101)

    def testNamedParameters(self):
        host = Host(authport=123, acctport=456, coaport=789, dict=101)
        self.assertEqual(host.authport, 123)
        self.assertEqual(host.acctport, 456)
        self.assertEqual(host.coaport, 789)
        self.assertEqual(host.dict, 101)


class PacketCreationTests(unittest.TestCase):
    def setUp(self):
        self.host = Host()

    def testCreatePacket(self):
        packet = self.host.create_packet(id=15)
        self.failUnless(isinstance(packet, Packet))
        self.failUnless(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)

    def testCreateAuthPacket(self):
        packet = self.host.create_auth_packet(id=15)
        self.failUnless(isinstance(packet, AuthPacket))
        self.failUnless(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)

    def testCreateAcctPacket(self):
        packet = self.host.create_acct_packet(id=15)
        self.failUnless(isinstance(packet, AcctPacket))
        self.failUnless(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)


class MockPacket:
    packet = object()
    replypacket = object()
    source = object()

    def Packet(self):
        return self.packet

    def create_raw_reply(self):
        return self.replypacket


class MockFd:
    data = None
    target = None

    def sendto(self, data, target):
        self.data = data
        self.target = target


class PacketSendTest(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.fd = MockFd()
        self.packet = MockPacket()

    def testSendPacket(self):
        self.host.send_packet(self.fd, self.packet)
        self.failUnless(self.fd.data is self.packet.packet)
        self.failUnless(self.fd.target is self.packet.source)

    def testSendReplyPacket(self):
        self.host.send_reply_packet(self.fd, self.packet)
        self.failUnless(self.fd.data is self.packet.replypacket)
        self.failUnless(self.fd.target is self.packet.source)
