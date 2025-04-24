import asyncio
import socket
import unittest
from unittest.mock import patch

import sipmessage

from sipua.transport import (
    AUTO_HOST,
    TransportAddress,
    TransportLayer,
    get_transport_destination,
    update_request_via,
)

from .utils import asynctest, lf2crlf

OPTIONS = lf2crlf("""INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 1.2.3.4:12345;branch=z9hG4bK1e5b2b763d;rport
Max-Forwards: 70
To: sip:bob@example.com
From: sip:alice@example.com;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

""")


class TransportTest(unittest.TestCase):
    @asynctest
    async def test_receive_request_send_response(self) -> None:
        received: list[sipmessage.Message] = []

        async def message_handler(message: sipmessage.Message) -> None:
            received.append(message)

        transport = TransportLayer(message_handler=message_handler)
        await transport.listen(
            TransportAddress(protocol="udp", host="127.0.0.1", port=5060)
        )

        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 5432))

            # Receive garbage.
            sock.sendto(b"", ("127.0.0.1", 5060))
            await asyncio.sleep(0.1)

            self.assertEqual(received, [])

            # Receive request.
            sock.sendto(OPTIONS.encode(), ("127.0.0.1", 5060))
            await asyncio.sleep(0.1)

            self.assertEqual(len(received), 1)
            request = received[0]
            assert isinstance(request, sipmessage.Request)
            self.assertEqual(request.method, "INVITE")
            self.assertEqual(
                request.uri,
                sipmessage.URI(
                    scheme="sip",
                    host="example.com",
                    user="bob",
                ),
            )
            self.assertEqual(
                request.via,
                [
                    sipmessage.Via(
                        transport="UDP",
                        host="1.2.3.4",
                        port=12345,
                        parameters=sipmessage.Parameters(
                            branch="z9hG4bK1e5b2b763d",
                            rport="5432",
                            received="127.0.0.1",
                        ),
                    )
                ],
            )

            # Send response.
            response = sipmessage.Response(200, "OK")
            response.via = request.via
            response.to_address = request.to_address
            response.from_address = request.from_address
            response.call_id = request.call_id
            response.cseq = request.cseq
            is_reliable = await transport.send_message(response)
            self.assertFalse(is_reliable)

            data, addr = sock.recvfrom(2000)
            self.assertEqual(
                data,
                lf2crlf("""SIP/2.0 200 OK
Via: SIP/2.0/UDP 1.2.3.4:12345;branch=z9hG4bK1e5b2b763d;rport=5432;received=127.0.0.1
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

""").encode(),
            )
            self.assertEqual(addr, ("127.0.0.1", 5060))

        await transport.close()

    @asynctest
    async def test_send_request(self) -> None:
        received: list[sipmessage.Message] = []

        async def message_handler(message: sipmessage.Message) -> None:
            received.append(message)

        transport = TransportLayer(message_handler=message_handler)
        await transport.listen(
            TransportAddress(protocol="udp", host="127.0.0.1", port=5060)
        )

        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 5432))

            # Send request.
            request = sipmessage.Request(
                method="OPTIONS",
                uri=sipmessage.URI(
                    scheme="sip", user="bob", host="127.0.0.1", port=5432
                ),
            )
            request.via = [
                sipmessage.Via(
                    transport="UDP",
                    host=AUTO_HOST,
                    parameters=sipmessage.Parameters(branch="z9hG4bK1e5b2b763d"),
                )
            ]
            request.max_forwards = 70
            request.to_address = sipmessage.Address.parse("sip:bob@example.com")
            request.from_address = sipmessage.Address.parse(
                "sip:alice@example.com;tag=7bc759c98ae3e112"
            )
            request.call_id = "126a8db08eba7fb6"
            request.cseq = sipmessage.CSeq(1, "OPTIONS")
            request.contact = [
                sipmessage.Address(
                    uri=sipmessage.URI(
                        scheme="sip",
                        host=AUTO_HOST,
                    )
                )
            ]
            await transport.send_message(request)

            data, addr = sock.recvfrom(2000)
            self.assertEqual(
                data,
                lf2crlf("""OPTIONS sip:bob@127.0.0.1:5432 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1e5b2b763d
Max-Forwards: 70
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Contact: <sip:127.0.0.1:5060;transport=udp>
Content-Length: 0

""").encode(),
            )
            self.assertEqual(addr, ("127.0.0.1", 5060))

        await transport.close()


class GetTransportDestinationTest(unittest.TestCase):
    @asynctest
    async def test_request_sip(self) -> None:
        request = sipmessage.Request(
            method="INVITE", uri=sipmessage.URI(scheme="sip", host="1.2.3.4")
        )
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="udp", host="1.2.3.4", port=5060),
        )

    @asynctest
    async def test_request_sip_loose_routing(self) -> None:
        """
        A Route is specified, using loose routing.
        """
        request = sipmessage.Request(
            method="INVITE", uri=sipmessage.URI(scheme="sip", host="1.2.3.4")
        )
        request.route = [
            sipmessage.Address(
                uri=sipmessage.URI(
                    scheme="sip",
                    host="2.3.4.5",
                    parameters=sipmessage.Parameters(lr=None),
                )
            )
        ]
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="udp", host="2.3.4.5", port=5060),
        )

    @asynctest
    async def test_request_sip_strict_routing(self) -> None:
        """
        A Route is specified, using strict routing.
        """
        request = sipmessage.Request(
            method="INVITE", uri=sipmessage.URI(scheme="sip", host="1.2.3.4")
        )
        request.route = [
            sipmessage.Address(uri=sipmessage.URI(scheme="sip", host="2.3.4.5"))
        ]
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="udp", host="1.2.3.4", port=5060),
        )

    @asynctest
    async def test_request_sip_transport_udp(self) -> None:
        """
        UDP transport is explicitly specified in the Request-URI and
        the host is a numeric IP address.
        """
        request = sipmessage.Request(
            method="INVITE",
            uri=sipmessage.URI(
                scheme="sip",
                host="1.2.3.4",
                parameters=sipmessage.Parameters(transport="udp"),
            ),
        )
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="udp", host="1.2.3.4", port=5060),
        )

    @asynctest
    async def test_request_sip_transport_udp_fqdn(self) -> None:
        """
        UDP transport is explicitly specified in the Request-URI and
        the host is an FQDN.
        """
        request = sipmessage.Request(
            method="INVITE",
            uri=sipmessage.URI(
                scheme="sip",
                host="atlanta.com",
                parameters=sipmessage.Parameters(transport="udp"),
            ),
        )
        with self.assertRaises(NotImplementedError) as cm:
            await get_transport_destination(request)
        self.assertEqual(str(cm.exception), "SRV lookups are not yet supported")

    @asynctest
    async def test_request_sip_transport_udp_fqdn_with_port(self) -> None:
        """
        UDP transport is explicitly specified in the Request-URI and
        the host is an FQDN.
        """
        request = sipmessage.Request(
            method="INVITE",
            uri=sipmessage.URI(
                scheme="sip",
                host="atlanta.com",
                port=5060,
                parameters=sipmessage.Parameters(transport="udp"),
            ),
        )
        with patch("socket.gethostbyname") as mock_gethostbyname:
            mock_gethostbyname.return_value = "1.2.3.4"
            self.assertEqual(
                await get_transport_destination(request),
                TransportAddress(protocol="udp", host="1.2.3.4", port=5060),
            )

    @asynctest
    async def test_request_sip_transport_tcp(self) -> None:
        """
        TCP transport is explicitly specified in the Request-URI and
        the host is a numeric IP address.
        """
        request = sipmessage.Request(
            method="INVITE",
            uri=sipmessage.URI(
                scheme="sip",
                host="1.2.3.4",
                parameters=sipmessage.Parameters(transport="tcp"),
            ),
        )
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="tcp", host="1.2.3.4", port=5060),
        )

    @asynctest
    async def test_request_sip_transport_ws_fqdn(self) -> None:
        """
        WS transport is explicitly specified in the Request-URI and
        the host is an FQDN.
        """
        request = sipmessage.Request(
            method="INVITE",
            uri=sipmessage.URI(
                scheme="sip",
                host="example.com",
                parameters=sipmessage.Parameters(transport="ws"),
            ),
        )
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="ws", host="example.com", port=0),
        )

    @asynctest
    async def test_request_sip_fqdn(self) -> None:
        # NOTE: this should theoretically trigger an NAPTR lookup.
        request = sipmessage.Request(
            method="INVITE", uri=sipmessage.URI(scheme="sip", host="atlanta.com")
        )
        with self.assertRaises(NotImplementedError) as cm:
            await get_transport_destination(request)
        self.assertEqual(str(cm.exception), "SRV lookups are not yet supported")

    @asynctest
    async def test_request_sips(self) -> None:
        request = sipmessage.Request(
            method="INVITE", uri=sipmessage.URI(scheme="sips", host="1.2.3.4")
        )
        self.assertEqual(
            await get_transport_destination(request),
            TransportAddress(protocol="tls", host="1.2.3.4", port=5061),
        )

    @asynctest
    async def test_request_sips_fqdn(self) -> None:
        # NOTE: this should theoretically trigger an NAPTR lookup.
        request = sipmessage.Request(
            method="INVITE", uri=sipmessage.URI(scheme="sips", host="atlanta.com")
        )
        with self.assertRaises(NotImplementedError) as cm:
            await get_transport_destination(request)
        self.assertEqual(str(cm.exception), "SRV lookups are not yet supported")

    @asynctest
    async def test_response_tcp(self) -> None:
        response = sipmessage.Response(code=200, phrase="OK")
        response.via = [sipmessage.Via(transport="TCP", host="1.2.3.4")]
        self.assertEqual(
            await get_transport_destination(response),
            TransportAddress(protocol="tcp", host="1.2.3.4", port=5060),
        )

    @asynctest
    async def test_response_tls(self) -> None:
        response = sipmessage.Response(code=200, phrase="OK")
        response.via = [sipmessage.Via(transport="TLS", host="1.2.3.4")]
        self.assertEqual(
            await get_transport_destination(response),
            TransportAddress(protocol="tls", host="1.2.3.4", port=5061),
        )

    @asynctest
    async def test_response_udp(self) -> None:
        response = sipmessage.Response(code=200, phrase="OK")
        response.via = [sipmessage.Via(transport="UDP", host="1.2.3.4")]
        self.assertEqual(
            await get_transport_destination(response),
            TransportAddress(protocol="udp", host="1.2.3.4", port=5060),
        )

    @asynctest
    async def test_response_udp_with_received_and_rport(self) -> None:
        response = sipmessage.Response(code=200, phrase="OK")
        response.via = [
            sipmessage.Via(
                transport="UDP",
                host="example.com",
                parameters=sipmessage.Parameters(received="1.2.3.4", rport="1234"),
            )
        ]
        self.assertEqual(
            await get_transport_destination(response),
            TransportAddress(protocol="udp", host="1.2.3.4", port=1234),
        )

    @asynctest
    async def test_response_ws(self) -> None:
        response = sipmessage.Response(code=200, phrase="OK")
        response.via = [sipmessage.Via(transport="WS", host="mYn6S3lQaKjo.invalid")]
        self.assertEqual(
            await get_transport_destination(response),
            TransportAddress(protocol="ws", host="mYn6S3lQaKjo.invalid", port=0),
        )

    @asynctest
    async def test_response_wss(self) -> None:
        response = sipmessage.Response(code=200, phrase="OK")
        response.via = [sipmessage.Via(transport="WSS", host="mYn6S3lQaKjo.invalid")]
        self.assertEqual(
            await get_transport_destination(response),
            TransportAddress(protocol="wss", host="mYn6S3lQaKjo.invalid", port=0),
        )


class UpdateRequestViaTest(unittest.TestCase):
    def test_no_via(self) -> None:
        request = sipmessage.Request(
            "INVITE", sipmessage.URI(scheme="sip", user="bob", host="biloxi.com")
        )
        update_request_via(request, "1.2.3.4", 5060)
        self.assertEqual(request.via, [])

    def test_via_received_different_host(self) -> None:
        request = sipmessage.Request(
            "INVITE", sipmessage.URI(scheme="sip", user="bob", host="biloxi.com")
        )
        request.via = [
            sipmessage.Via(
                transport="UDP",
                host="bobspc.biloxi.com",
            )
        ]
        update_request_via(request, "1.2.3.4", 5060)
        self.assertEqual(
            request.via,
            [
                sipmessage.Via(
                    transport="UDP",
                    host="bobspc.biloxi.com",
                    parameters=sipmessage.Parameters(received="1.2.3.4"),
                )
            ],
        )

    def test_via_received_same_host(self) -> None:
        request = sipmessage.Request(
            "INVITE", sipmessage.URI(scheme="sip", user="bob", host="biloxi.com")
        )
        request.via = [sipmessage.Via(transport="UDP", host="1.2.3.4")]
        update_request_via(request, "1.2.3.4", 5060)
        self.assertEqual(request.via, [sipmessage.Via(transport="UDP", host="1.2.3.4")])

    def test_via_rport(self) -> None:
        request = sipmessage.Request(
            "INVITE", sipmessage.URI(scheme="sip", user="bob", host="biloxi.com")
        )
        request.via = [
            sipmessage.Via(
                transport="UDP",
                host="1.2.3.4",
                parameters=sipmessage.Parameters(rport=None),
            )
        ]
        update_request_via(request, "1.2.3.4", 5060)
        self.assertEqual(
            request.via,
            [
                sipmessage.Via(
                    transport="UDP",
                    host="1.2.3.4",
                    parameters=sipmessage.Parameters(rport="5060"),
                )
            ],
        )
