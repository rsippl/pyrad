#!/usr/bin/env python3
import sys
from os import path

from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode


def main(path_to_dictionary, coa_type, nas_identifier):
    # create coa client
    client = Client(server='127.0.0.1',
                    secret=b'Kah3choteereethiejeimaeziecumi',
                    dict=Dictionary(path_to_dictionary))

    # set coa timeout
    client.timeout = 30

    # create coa request packet
    attributes = {
        'Acct-Session-Id': '1337',
        'NAS-Identifier': nas_identifier,
    }

    if coa_type == 'coa':
        # create coa request
        request = client.CreateCoAPacket(**attributes)
    elif coa_type == 'dis':
        # create disconnect request
        request = client.CreateCoAPacket(
            code=PacketCode.DisconnectRequest,
            **attributes)
    else:
        sys.exit(1)

    # send request
    result = client.SendPacket(request)
    print(result)
    print(result.code)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: coa.py {coa|dis} daemon-1234')
        sys.exit(1)

    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')

    main(dictionary, sys.argv[1], sys.argv[2])
