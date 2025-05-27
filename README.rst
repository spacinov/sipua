.. image:: docs/_static/sipua.svg
   :width: 120px
   :alt: sipua

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

.. image:: https://readthedocs.org/projects/sipua/badge/?version=latest
   :target: https://sipua.readthedocs.io/
   :alt: Documentation

The ``sipua`` project provides a library for writing SIP user agents in Python,
with a focus on correctness and composability. It can be used to write clients,
servers or proxies.

Its features include:

- A transport layer supporting UDP, TCP and WebSocket.
- A transaction layer for stateful user agents and proxies.
- An RTP and RTCP stack with optional support for `ICE`_ and `DTLS-SRTP`_.
- Support for Opus, G.722, PCMU and PCMA audio codecs.

To learn more about ``sipua`` please `read the documentation`_.

License
-------

``sipua`` is released under the `BSD license`_.

.. _ICE: https://datatracker.ietf.org/doc/html/rfc8445
.. _DTLS-SRTP: https://datatracker.ietf.org/doc/html/rfc5764
.. _read the documentation: https://sipua.readthedocs.io/en/stable/
.. _BSD license: https://sipua.readthedocs.io/en/stable/license.html
