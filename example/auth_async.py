#!/usr/bin/env python3

import asyncio
import logging
import traceback

from os import path

from pyrad.client_async import ClientAsync
from pyrad.dictionary import Dictionary
from pyrad.packet import PacketCode

logging.basicConfig(level='DEBUG',
                    format='%(asctime)s [%(levelname)-8s] %(message)s')


def create_request(client, user):
    return client.create_auth_packet(**{
        'User-Name': user,
        'NAS-IP-Address': '192.168.1.10',
        'NAS-Port': 0,
        'Service-Type': 'Login-User',
        'NAS-Identifier': 'trillian',
        'Called-Station-Id': '00-04-5F-00-0F-D1',
        'Calling-Station-Id': '00-01-24-80-B3-9C',
        'Framed-IP-Address': '10.0.0.100',
    })


def print_reply(reply):
    if reply.code == PacketCode.ACCESS_ACCEPT:
        print('Access accepted')
    else:
        print('Access denied')

    print('Attributes returned by server:')
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))


def initialize_transport(loop, client):
    loop.run_until_complete(
        asyncio.ensure_future(
            client.initialize_transports(enable_auth=True,
                                         local_addr='127.0.0.1',
                                         local_auth_port=8000,
                                         enable_acct=True,
                                         enable_coa=True)))


def main(path_to_dictionary):
    client = ClientAsync(server='localhost',
                         secret=b'Kah3choteereethiejeimaeziecumi',
                         timeout=4,
                         dict=Dictionary(path_to_dictionary))

    loop = asyncio.get_event_loop()

    try:
        # Initialize transports
        initialize_transport(loop, client)

        requests = []
        for i in range(255):
            req = create_request(client, f'user{i}')
            future = client.send_packet(req)
            requests.append(future)

        # Send auth requests asynchronously to the server
        loop.run_until_complete(asyncio.ensure_future(
            asyncio.gather(
                *requests,
                return_exceptions=True
            )

        ))

        for future in requests:
            if future.exception():
                print('EXCEPTION ', future.exception())
            else:
                reply = future.result()
                print_reply(reply)

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            client.deinitialize_transports()))
        print('END')
    except Exception as exc:
        print('Error: ', exc)
        traceback.print_exc()

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            client.deinitialize_transports()))

    loop.close()


if __name__ == '__main__':
    dictionary = path.join(path.dirname(path.abspath(__file__)), 'dictionary')
    main(dictionary)
