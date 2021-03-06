.. image:: https://travis-ci.org/pyradius/pyrad.svg?branch=master
    :target: https://travis-ci.org/pyradius/pyrad
.. image:: https://coveralls.io/repos/github/pyradius/pyrad/badge.svg?branch=master
    :target: https://coveralls.io/github/pyradius/pyrad?branch=master
.. image:: https://img.shields.io/pypi/v/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad
.. image:: https://img.shields.io/pypi/pyversions/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad
.. image:: https://img.shields.io/pypi/dm/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad
.. image:: https://readthedocs.org/projects/pyrad/badge/?version=latest
    :target: http://pyrad.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/l/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad

Introduction
============

pyrad is an implementation of a RADIUS client/server as described in RFC2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses.

Here is an example of doing a authentication request::

    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    from pyrad.packet import PacketCode

    client = Client(server="localhost", secret=b"Kah3choteereethiejeimaeziecumi",
                    dict=Dictionary("dictionary"))

    # create request
    req = client.create_auth_packet(code=PacketCode.ACCESS_REQUEST,
                                    User_Name="wichert", NAS_Identifier="localhost")
    req["User-Password"] = req.pw_crypt("password")

    # send request
    reply = client.send_packet(req)

    if reply.code == PacketCode.ACCESS_ACCEPT:
        print("access accepted")
    else:
        print("access denied")

    print("Attributes returned by server:")
    for key in reply.keys():
        print("{key}: {reply[key]}")



Requirements & Installation
===========================

pyrad requires Python 3.6 or later

Installing is simple; pyrad uses the standard distutils system for installing
Python modules::

  python setup.py install


Author, Copyright, Availability
===============================

pyrad was written by Wichert Akkerman <wichert@wiggy.net> and is maintained by 
Christian Giese (GIC-de) and Istvan Ruzman (Istvan91).

This project is licensed under a BSD license.

Copyright and license information can be found in the LICENSE.txt file.

The current version and documentation can be found on pypi:
https://pypi.org/project/pyrad/

Bugs and wishes can be submitted in the pyrad issue tracker on github:
https://github.com/pyradius/pyrad/issues
