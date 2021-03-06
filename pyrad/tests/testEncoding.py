import unittest
from ipaddress import AddressValueError

from pyrad import encoding


class EncodingTests(unittest.TestCase):
    def testEncodeString(self):
        self.assertEqual(
            encoding.encode_string('1234567890'),
            b'1234567890')
        self.assertRaises(ValueError, encoding.encode_string, 'x' * 254)
        self.assertRaises(TypeError, encoding.encode_string, 1)

    def testEncodeAddress(self):
        self.assertEqual(
            encoding.encode_ipv4_address('192.168.0.255'),
            b'\xc0\xa8\x00\xff')
        self.assertRaises(AddressValueError, encoding.encode_ipv4_address, 'TEST123')
        self.assertRaises(TypeError, encoding.encode_ipv4_address, 1)

    def testEncodeInteger(self):
        self.assertEqual(encoding.encode_integer(0x01020304), b'\x01\x02\x03\x04')

    def testEncodeInteger64(self):
        self.assertEqual(
            encoding.encode_integer_64(0xFFFFFFFFFFFFFFFF), b'\xff' * 8
        )

    def testEncodeUnsignedInteger(self):
        self.assertEqual(encoding.encode_integer(0xFFFFFFFF), b'\xff\xff\xff\xff')
        self.assertRaises(TypeError, encoding.encode_integer, 'ONE')

    def testEncodeDate(self):
        self.assertEqual(encoding.encode_date(0x01020304), b'\x01\x02\x03\x04')
        self.assertRaises(TypeError, encoding.encode_date, '1')

    def testEncodeAscendBinary(self):
        self.assertEqual(
            encoding.encode_ascend_binary(
                'family=ipv4 action=discard direction=in dst=10.10.255.254/32'),
            b'\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 '
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testEncodeIPv6Prefix(self):
        self.assertEqual(
            encoding.encode_ipv6_prefix('fc66::/64'),
            b'\x00\x40\xfc\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testDecodeString(self):
        self.assertEqual(
            encoding.decode_string(b'1234567890'),
            '1234567890')

    def testDecodeAddress(self):
        self.assertEqual(
            encoding.decode_ipv4_address(b'\xc0\xa8\x00\xff'),
            '192.168.0.255')

    def testDecodeInteger(self):
        self.assertEqual(
            encoding.decode_integer(b'\x01\x02\x03\x04'),
            0x01020304)

    def testDecodeInteger64(self):
        self.assertEqual(
            encoding.decode_integer_64(b'\xff' * 8), 0xFFFFFFFFFFFFFFFF
        )

    def testDecodeDate(self):
        self.assertEqual(
            encoding.decode_date(b'\x01\x02\x03\x04'),
            0x01020304)

    def testDecodeIPv6Prefix(self):
        self.assertEqual(
            encoding.decode_ipv6_prefix(
                b'\x00\x40\xfc\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
            'fc66::/64')

    def testEncodeAttr(self):
        self.assertEqual(
            encoding.encode_attr('string', 'string'),
            b'string')
        self.assertEqual(
            encoding.encode_attr('octets', b'string'),
            b'string')
        self.assertEqual(
            encoding.encode_attr('ipaddr', '192.168.0.255'),
            b'\xc0\xa8\x00\xff')
        self.assertEqual(
            encoding.encode_attr('integer', 0x01020304),
            b'\x01\x02\x03\x04')
        self.assertEqual(
            encoding.encode_attr('date', 0x01020304),
            b'\x01\x02\x03\x04')
        self.assertEqual(
            encoding.encode_attr('integer64', 0xFFFFFFFFFFFFFFFF),
            b'\xff' * 8)
        self.assertRaises(ValueError, encoding.encode_attr, 'unknown', None)

    def testDecodeAttr(self):
        self.assertEqual(
            encoding.decode_attr('string', b'string'),
            'string')
        self.assertEqual(
            encoding.encode_attr('octets', b'string'),
            b'string')
        self.assertEqual(
            encoding.decode_attr('ipaddr', b'\xc0\xa8\x00\xff'),
            '192.168.0.255')
        self.assertEqual(
            encoding.decode_attr('integer', b'\x01\x02\x03\x04'),
            0x01020304)
        self.assertEqual(
            encoding.decode_attr('integer64', b'\xff' * 8),
            0xFFFFFFFFFFFFFFFF)
        self.assertEqual(
            encoding.decode_attr('date', b'\x01\x02\x03\x04'),
            0x01020304)
        self.assertRaises(ValueError, encoding.decode_attr, 'unknown', None)
