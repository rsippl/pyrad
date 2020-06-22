#!/usr/bin/env python3
import socket
import sys
from os import path

import pyrad
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode


def main(path_to_dictionary):
    srv = Client(server='localhost',
                 authport=18121,
                 secret=b'test',
                 dict=Dictionary(path_to_dictionary))

    req = srv.CreateAuthPacket(
        code=PacketCode.STATUS_SERVER,
        FreeRADIUS_Statistics_Type='All',
    )
    req.add_message_authenticator()

    try:
        print('Sending FreeRADIUS status request')
        reply = srv.SendPacket(req)
    except pyrad.client.Timeout:
        print('RADIUS server does not reply')
        sys.exit(1)
    except socket.error as error:
        print('Network error: ' + error[1])
        sys.exit(1)

    print('Attributes returned by server:')
    for key, value in reply.items():
        print(f'{key}: {value}')


if __name__ == '__main__':
    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')
    main(dictionary)
