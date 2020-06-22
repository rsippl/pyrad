#!/usr/bin/env python3
import socket
import sys
from os import path

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode


def main(path_to_dictionary):
    srv = Client(server='127.0.0.1',
                 secret=b'Kah3choteereethiejeimaeziecumi',
                 dict=Dictionary(path_to_dictionary))

    req = srv.CreateAuthPacket(
        code=PacketCode.ACCESS_REQUEST,
        **{
            'User-Name': 'wichert',
            'NAS-IP-Address': '192.168.1.10',
            'NAS-Port': 0,
            'Service-Type': 'Login-User',
            'NAS-Identifier': 'trillian',
            'Called-Station-Id': '00-04-5F-00-0F-D1',
            'Calling-Station-Id': '00-01-24-80-B3-9C',
            'Framed-IP-Address': '10.0.0.100',
        })

    try:
        print('Sending authentication request')
        reply = srv.SendPacket(req)
    except Timeout:
        print('RADIUS server does not reply')
        sys.exit(1)
    except socket.error as error:
        print('Network error: ' + error[1])
        sys.exit(1)

    if reply.code == PacketCode.ACCESS_ACCEPT:
        print('Access accepted')
    else:
        print('Access denied')

    print('Attributes returned by server:')
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))


if __name__ == '__main__':
    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')
    main(dictionary)
