import unittest
from ipaddress import AddressValueError

from pyrad import tools


class EncodingTests(unittest.TestCase):
    def testEncodeString(self):
        self.assertEqual(
            tools.EncodeString('1234567890'),
            b'1234567890')
        self.assertRaises(ValueError, tools.EncodeString, 'x' * 254)
        self.assertRaises(TypeError, tools.EncodeString, 1)

    def testEncodeAddress(self):
        self.assertEqual(
            tools.EncodeAddress('192.168.0.255'),
            b'\xc0\xa8\x00\xff')
        self.assertRaises(AddressValueError, tools.EncodeAddress, 'TEST123')
        self.assertRaises(TypeError, tools.EncodeAddress, 1)

    def testEncodeInteger(self):
        self.assertEqual(tools.EncodeInteger(0x01020304), b'\x01\x02\x03\x04')

    def testEncodeInteger64(self):
        self.assertEqual(
            tools.EncodeInteger64(0xFFFFFFFFFFFFFFFF), b'\xff' * 8
        )

    def testEncodeUnsignedInteger(self):
        self.assertEqual(tools.EncodeInteger(0xFFFFFFFF), b'\xff\xff\xff\xff')
        self.assertRaises(TypeError, tools.EncodeInteger, 'ONE')

    def testEncodeDate(self):
        self.assertEqual(tools.EncodeDate(0x01020304), b'\x01\x02\x03\x04')
        self.assertRaises(TypeError, tools.EncodeDate, '1')

    def testEncodeAscendBinary(self):
        self.assertEqual(
            tools.EncodeAscendBinary(
                'family=ipv4 action=discard direction=in dst=10.10.255.254/32'),
            b'\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 '
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testEncodeIPv6Prefix(self):
        self.assertEqual(
            tools.EncodeIPv6Prefix('fc66::/64'),
            b'\x00\x40\xfc\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testDecodeString(self):
        self.assertEqual(
            tools.DecodeString(b'1234567890'),
            '1234567890')

    def testDecodeAddress(self):
        self.assertEqual(
            tools.DecodeAddress(b'\xc0\xa8\x00\xff'),
            '192.168.0.255')

    def testDecodeInteger(self):
        self.assertEqual(
            tools.DecodeInteger(b'\x01\x02\x03\x04'),
            0x01020304)

    def testDecodeInteger64(self):
        self.assertEqual(
            tools.DecodeInteger64(b'\xff' * 8), 0xFFFFFFFFFFFFFFFF
        )

    def testDecodeDate(self):
        self.assertEqual(
            tools.DecodeDate(b'\x01\x02\x03\x04'),
            0x01020304)

    def testDecodeIPv6Prefix(self):
        self.assertEqual(
            tools.DecodeIPv6Prefix(
                b'\x00\x40\xfc\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
            'fc66::/64')

    def testEncodeAttr(self):
        self.assertEqual(
            tools.EncodeAttr('string', 'string'),
            b'string')
        self.assertEqual(
            tools.EncodeAttr('octets', b'string'),
            b'string')
        self.assertEqual(
            tools.EncodeAttr('ipaddr', '192.168.0.255'),
            b'\xc0\xa8\x00\xff')
        self.assertEqual(
            tools.EncodeAttr('integer', 0x01020304),
            b'\x01\x02\x03\x04')
        self.assertEqual(
            tools.EncodeAttr('date', 0x01020304),
            b'\x01\x02\x03\x04')
        self.assertEqual(
            tools.EncodeAttr('integer64', 0xFFFFFFFFFFFFFFFF),
            b'\xff' * 8)
        self.assertRaises(ValueError, tools.EncodeAttr, 'unknown', None)

    def testDecodeAttr(self):
        self.assertEqual(
            tools.DecodeAttr('string', b'string'),
            'string')
        self.assertEqual(
            tools.EncodeAttr('octets', b'string'),
            b'string')
        self.assertEqual(
            tools.DecodeAttr('ipaddr', b'\xc0\xa8\x00\xff'),
            '192.168.0.255')
        self.assertEqual(
            tools.DecodeAttr('integer', b'\x01\x02\x03\x04'),
            0x01020304)
        self.assertEqual(
            tools.DecodeAttr('integer64', b'\xff' * 8),
            0xFFFFFFFFFFFFFFFF)
        self.assertEqual(
            tools.DecodeAttr('date', b'\x01\x02\x03\x04'),
            0x01020304)
        self.assertRaises(ValueError, tools.DecodeAttr, 'unknown', None)
