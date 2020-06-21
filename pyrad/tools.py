# tools.py
#
# Utility functions
import binascii
import ipaddress
import struct


def EncodeString(string):
    if len(string) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    if isinstance(string, str):
        return string.encode('utf-8')
    return string


def EncodeOctets(string):
    if len(string) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')

    if string.startswith(b'0x'):
        hexstring = string.split(b'0x')[1]
        return binascii.unhexlify(hexstring)
    else:
        return string


def EncodeAddress(addr):
    if not isinstance(addr, str):
        raise TypeError('Address has to be a string')
    return ipaddress.IPv4Address(addr).packed


def EncodeIPv6Prefix(addr):
    if not isinstance(addr, str):
        raise TypeError('IPv6 Prefix has to be a string')
    ip = ipaddress.IPv6Network(addr)
    return struct.pack('BB', 0, ip.prefixlen) + ip.network_address.packed


def EncodeIPv6Address(addr):
    if not isinstance(addr, str):
        raise TypeError('IPv6 Address has to be a string')
    return ipaddress.IPv6Address(addr).packed


def EncodeAscendBinary(string):
    """
    Format: List of type=value pairs sperated by spaces.

    Example: 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'

    Type:
        family      ipv4(default) or ipv6
        action      discard(default) or accept
        direction   in(default) or out
        src         source prefix (default ignore)
        dst         destination prefix (default ignore)
        proto       protocol number / next-header number (default ignore)
        sport       source port (default ignore)
        dport       destination port (default ignore)
        sportq      source port qualifier (default 0)
        dportq      destination port qualifier (default 0)

    Source/Destination Port Qualifier:
        0   no compare
        1   less than
        2   equal to
        3   greater than
        4   not equal to
    """

    terms = {
        'family':       b'\x01',
        'action':       b'\x00',
        'direction':    b'\x01',
        'src':          b'\x00\x00\x00\x00',
        'dst':          b'\x00\x00\x00\x00',
        'srcl':         b'\x00',
        'dstl':         b'\x00',
        'proto':        b'\x00',
        'sport':        b'\x00\x00',
        'dport':        b'\x00\x00',
        'sportq':       b'\x00',
        'dportq':       b'\x00'
    }

    for t in string.split(' '):
        key, value = t.split('=')
        if key == 'family' and value == 'ipv6':
            terms[key] = b'\x03'
            if terms['src'] == b'\x00\x00\x00\x00':
                terms['src'] = 16 * b'\x00'
            if terms['dst'] == b'\x00\x00\x00\x00':
                terms['dst'] = 16 * b'\x00'
        elif key == 'action' and value == 'accept':
            terms[key] = b'\x01'
        elif key == 'direction' and value == 'out':
            terms[key] = b'\x00'
        elif key in ('src', 'dst'):
            ip = ipaddress.ip_network(value)
            terms[key] = ip.network_address.packed
            terms[key + 'l'] = struct.pack('B', ip.prefixlen)
        elif key in ('sport', 'dport'):
            terms[key] = struct.pack('!H', int(value))
        elif key in ('sportq', 'dportq', 'proto'):
            terms[key] = struct.pack('B', int(value))

    trailer = 8 * b'\x00'

    result = b''.join((
        terms['family'], terms['action'], terms['direction'], b'\x00',
        terms['src'], terms['dst'], terms['srcl'], terms['dstl'], terms['proto'], b'\x00',
        terms['sport'], terms['dport'], terms['sportq'], terms['dportq'], b'\x00\x00', trailer))
    return result


def EncodeInteger(num, format='!I'):
    try:
        num = int(num)
    except ValueError:
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack(format, num)


def EncodeInteger64(num, format='!Q'):
    try:
        num = int(num)
    except ValueError:
        raise TypeError('Can not encode non-integer as integer64')
    return struct.pack(format, num)


def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError('Can not encode non-integer as date')
    return struct.pack('!I', num)


def DecodeString(string):
    try:
        return string.decode('utf-8')
    except:
        return string


def DecodeOctets(string):
    return string


def DecodeAddress(addr):
    return '.'.join((str(a) for a in struct.unpack('BBBB', addr)))


def DecodeIPv6Prefix(addr):
    addr = addr + b'\x00' * (18 - len(addr))
    prefix = addr[:2]
    addr = addr[2:]
    _, prefix = struct.unpack('BB', prefix)
    network = ipaddress.IPv6Network((addr, prefix))
    return str(network)


def DecodeIPv6Address(addr):
    addr = addr + b'\x00' * (16 - len(addr))
    return str(ipaddress.IPv6Address(addr))


def DecodeAscendBinary(string):
    return string


def DecodeInteger(num, format='!I'):
    return (struct.unpack(format, num))[0]


def DecodeInteger64(num, format='!Q'):
    return (struct.unpack(format, num))[0]


def DecodeDate(num):
    return (struct.unpack('!I', num))[0]


ENCODE_MAP = {
    'string': EncodeString,
    'octets': EncodeOctets,
    'integer': EncodeInteger,
    'ipaddr': EncodeAddress,
    'ipv6prefix': EncodeIPv6Prefix,
    'ipv6addr': EncodeIPv6Address,
    'abinary': EncodeAscendBinary,
    'signed': lambda value: EncodeInteger(value, '!i'),
    'short': lambda value: EncodeInteger(value, '!H'),
    'byte': lambda value: EncodeInteger(value, '!B'),
    'date': EncodeDate,
    'integer64': EncodeInteger64,
}


def EncodeAttr(datatype, value):
    try:
        return ENCODE_MAP[datatype](value)
    except KeyError:
        raise ValueError(f'Unknown attribute type {datatype}')


DECODE_MAP = {
    'string': DecodeString,
    'octets': DecodeOctets,
    'integer': DecodeInteger,
    'ipaddr': DecodeAddress,
    'ipv6prefix': DecodeIPv6Prefix,
    'ipv6addr': DecodeIPv6Address,
    'abinary': DecodeAscendBinary,
    'signed': lambda value: DecodeInteger(value, '!i'),
    'short': lambda value: DecodeInteger(value, '!H'),
    'byte': lambda value: DecodeInteger(value, '!B'),
    'date': DecodeDate,
    'integer64': DecodeInteger64,
}


def DecodeAttr(datatype, value):
    try:
        return DECODE_MAP[datatype](value)
    except KeyError:
        raise ValueError(f'Unknown attribute type {datatype}')
