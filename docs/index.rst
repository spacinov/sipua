sipua
=====

.. image:: https://img.shields.io/pypi/l/sipua.svg
   :target: https://pypi.python.org/pypi/sipua
   :alt: License

.. image:: https://img.shields.io/pypi/v/sipua.svg
   :target: https://pypi.python.org/pypi/sipua
   :alt: Version

.. image:: https://github.com/spacinov/sipua/workflows/tests/badge.svg
   :target: https://github.com/spacinov/sipua/actions
   :alt: Tests

.. image:: https://img.shields.io/codecov/c/github/spacinov/sipua.svg
   :target: https://codecov.io/gh/spacinov/sipua
   :alt: Coverage

The ``sipua`` project provides a library for writing SIP user agents in Python,
with a focus on correctness and composability. It can be used to write clients,
servers or proxies.

Its features include:

- A transport layer supporting UDP, TCP and WebSocket.
- A transaction layer for stateful user agents and proxies.
- An RTP and RTCP stack with optional support for `ICE`_ and `DTLS-SRTP`_.
- Support for PCMU, PCMA and Opus audio codecs.

.. toctree::
   :caption: API Reference
   :hidden:

   highlevel
   dialog
   transaction
   transport
   utils

.. toctree::
   :caption: About sipua
   :hidden:

   license

.. _ICE: https://datatracker.ietf.org/doc/html/rfc8445
.. _DTLS-SRTP: https://datatracker.ietf.org/doc/html/rfc5764
