#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#


import unittest

import sipmessage
from sipua.utils import create_ack, create_response

from .utils import lf2crlf, parse_request


class UtilsTest(unittest.TestCase):
    def assertMessage(
        self, message: sipmessage.Request | sipmessage.Response, data: bytes
    ) -> None:
        self.assertEqual(bytes(message), lf2crlf(data))

    def test_create_invite_response_and_ack(self) -> None:
        request = parse_request(b"""INVITE sip:+33233445566@127.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
Max-Forwards: 70
To: sip:+33233445566@127.0.0.1:5060
From: sip:+33122334455@127.0.0.1:43248;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 235

v=0
o=- 1695503748 1695503748 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 57299 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=silenceSupp:off - - - -
""")

        response = create_response(request=request, code=200)
        self.assertMessage(
            response,
            b"""SIP/2.0 200 OK
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
To: <sip:+33233445566@127.0.0.1:5060>
From: <sip:+33122334455@127.0.0.1:43248>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 INVITE

""",
        )

        # Create ACK for a response without a `Contact` header.
        # This is theoretically invalid.
        ack = create_ack(request=request, response=response)
        self.assertMessage(
            ack,
            b"""ACK sip:+33233445566@127.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
To: <sip:+33233445566@127.0.0.1:5060>
From: <sip:+33122334455@127.0.0.1:43248>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 ACK

""",
        )

        # Create ACK for a response with a `Contact` header.
        response.contact = [
            sipmessage.Address.parse("<sip:+33233445566@127.0.0.1:5060;foo=bar>")
        ]
        ack = create_ack(request=request, response=response)
        self.assertMessage(
            ack,
            b"""ACK sip:+33233445566@127.0.0.1:5060;foo=bar SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
To: <sip:+33233445566@127.0.0.1:5060>
From: <sip:+33122334455@127.0.0.1:43248>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 ACK

""",
        )

    def test_create_invite_response_and_ack_with_record_route(self) -> None:
        request = parse_request(b"""INVITE sip:callee@u2.domain.com SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
Max-Forwards: 70
To: sip:callee@127.0.0.1:5060
From: sip:+caller@127.0.0.1:43248;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
Contact: sip:caller@u1.example.com
CSeq: 1 INVITE
Content-Type: application/sdp
Record-Route: <sip:p2.domain.com;lr>
Record-Route: <sip:p1.example.com;lr>

v=0
o=- 1695503748 1695503748 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 57299 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=silenceSupp:off - - - -

""")
        response = create_response(request=request, code=200)
        self.assertMessage(
            response,
            b"""SIP/2.0 200 OK
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
To: <sip:callee@127.0.0.1:5060>
From: <sip:+caller@127.0.0.1:43248>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 INVITE
Record-Route: <sip:p2.domain.com;lr>
Record-Route: <sip:p1.example.com;lr>

""",
        )

        ack = create_ack(request=request, response=response)
        self.assertMessage(
            ack,
            b"""ACK sip:callee@u2.domain.com SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
To: <sip:callee@127.0.0.1:5060>
From: <sip:+caller@127.0.0.1:43248>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 ACK
Route: <sip:p1.example.com;lr>
Route: <sip:p2.domain.com;lr>

""",
        )
