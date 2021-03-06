
*********************************
:mod:`pyrad` -- RADIUS for Python
*********************************

:Author: Wichert Akkerman
:Version: |version|

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

pyrad requires Python 2.6 or later, or Python 3.2 or later

Installing is simple; pyrad uses the standard distutils system for installing
Python modules::

  python setup.py install


API Documentation
=================

Per-module :mod:`pyrad` API documentation.

.. toctree::
  :maxdepth: 2

  api/client
  api/dictionary
  api/host
  api/packet
  api/proxy
  api/server


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
