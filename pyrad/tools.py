# tools.py
#
# Utility functions
import binascii
import ipaddress
import struct


def encode_string(string):
    if len(string) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    if isinstance(string, str):
        return string.encode('utf-8')
    return string


def encode_octets(string):
    if len(string) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')

    if string.startswith(b'0x'):
        hexstring = string.split(b'0x')[1]
        return binascii.unhexlify(hexstring)
    else:
        return string


def encode_ipv4_address(addr):
    if not isinstance(addr, str):
        raise TypeError('Address has to be a string')
    return ipaddress.IPv4Address(addr).packed


def encode_ipv6_prefix(addr):
    if not isinstance(addr, str):
        raise TypeError('IPv6 Prefix has to be a string')
    ip = ipaddress.IPv6Network(addr)
    return struct.pack('BB', 0, ip.prefixlen) + ip.network_address.packed


def encode_ipv6_address(addr):
    if not isinstance(addr, str):
        raise TypeError('IPv6 Address has to be a string')
    return ipaddress.IPv6Address(addr).packed


def encode_ascend_binary(string):
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
        'family': b'\x01',
        'action': b'\x00',
        'direction': b'\x01',
        'src': b'\x00\x00\x00\x00',
        'dst': b'\x00\x00\x00\x00',
        'srcl': b'\x00',
        'dstl': b'\x00',
        'proto': b'\x00',
        'sport': b'\x00\x00',
        'dport': b'\x00\x00',
        'sportq': b'\x00',
        'dportq': b'\x00'
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


def encode_integer(num, format='!I'):
    try:
        num = int(num)
    except ValueError:
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack(format, num)


def encode_integer_64(num, format='!Q'):
    try:
        num = int(num)
    except ValueError:
        raise TypeError('Can not encode non-integer as integer64')
    return struct.pack(format, num)


def encode_date(num):
    if not isinstance(num, int):
        raise TypeError('Can not encode non-integer as date')
    return struct.pack('!I', num)


def decode_string(string):
    try:
        return string.decode('utf-8')
    except:
        return string


def decode_octets(string):
    return string


def decode_ipv4_address(addr):
    return '.'.join((str(a) for a in struct.unpack('BBBB', addr)))


def decode_ipv6_prefix(addr):
    addr = addr + b'\x00' * (18 - len(addr))
    prefix = addr[:2]
    addr = addr[2:]
    _, prefix = struct.unpack('BB', prefix)
    network = ipaddress.IPv6Network((addr, prefix))
    return str(network)


def decode_ipv6_address(addr):
    addr = addr + b'\x00' * (16 - len(addr))
    return str(ipaddress.IPv6Address(addr))


def decode_ascend_binary(string):
    return string


def decode_integer(num, format='!I'):
    return (struct.unpack(format, num))[0]


def decode_integer_64(num, format='!Q'):
    return (struct.unpack(format, num))[0]


def decode_date(num):
    return (struct.unpack('!I', num))[0]


ENCODE_MAP = {
    'string': encode_string,
    'octets': encode_octets,
    'integer': encode_integer,
    'ipaddr': encode_ipv4_address,
    'ipv6prefix': encode_ipv6_prefix,
    'ipv6addr': encode_ipv6_address,
    'abinary': encode_ascend_binary,
    'signed': lambda value: encode_integer(value, '!i'),
    'short': lambda value: encode_integer(value, '!H'),
    'byte': lambda value: encode_integer(value, '!B'),
    'date': encode_date,
    'integer64': encode_integer_64,
}


def encode_attr(datatype, value):
    try:
        return ENCODE_MAP[datatype](value)
    except KeyError:
        raise ValueError(f'Unknown attribute type {datatype}')


DECODE_MAP = {
    'string': decode_string,
    'octets': decode_octets,
    'integer': decode_integer,
    'ipaddr': decode_ipv4_address,
    'ipv6prefix': decode_ipv6_prefix,
    'ipv6addr': decode_ipv6_address,
    'abinary': decode_ascend_binary,
    'signed': lambda value: decode_integer(value, '!i'),
    'short': lambda value: decode_integer(value, '!H'),
    'byte': lambda value: decode_integer(value, '!B'),
    'date': decode_date,
    'integer64': decode_integer_64,
}


def decode_attr(datatype, value):
    try:
        return DECODE_MAP[datatype](value)
    except KeyError:
        raise ValueError(f'Unknown attribute type {datatype}')
