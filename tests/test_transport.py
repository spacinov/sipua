#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import asyncio
import contextlib
import dataclasses
import socket
import unittest
from collections.abc import AsyncGenerator
from unittest.mock import patch

import sipmessage
import websockets.asyncio.client
import websockets.asyncio.connection
from sipua.transport import (
    WEBSOCKET_SUBPROTOCOL,
    TransportAddress,
    TransportLayer,
    get_transport_destination,
    serialize_message,
    update_request_via,
)
from sipua.utils import create_contact, create_response, create_via

from .utils import asynctest, lf2crlf, parse_response


def create_request(
    *,
    uri_port: int,
    uri_transport: str | None = None,
) -> sipmessage.Request:
    uri = sipmessage.URI(scheme="sip", user="bob", host="127.0.0.1", port=uri_port)
    if uri_transport is not None:
        uri = dataclasses.replace(
            uri, parameters=sipmessage.Parameters(transport=uri_transport)
        )
    request = sipmessage.Request(method="OPTIONS", uri=uri)
    with patch("sipua.utils.random_string", new=lambda x: "1e5b2b763d"):
        request.via = [create_via()]
    request.max_forwards = 70
    request.to_address = sipmessage.Address.parse("sip:bob@example.com")
    request.from_address = sipmessage.Address.parse(
        "sip:alice@example.com;tag=7bc759c98ae3e112"
    )
    request.call_id = "126a8db08eba7fb6"
    request.cseq = sipmessage.CSeq(1, "OPTIONS")
    request.contact = [create_contact()]
    return request


def create_request_bytes(
    *,
    via_addr: str = "1.2.3.4:12345",
    via_transport: str,
) -> bytes:
    return lf2crlf(
        f"""INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/{via_transport} {via_addr};branch=z9hG4bK1e5b2b763d;rport
Max-Forwards: 70
To: sip:bob@example.com
From: sip:alice@example.com;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

    """.encode()
    )


def create_response_bytes(*, via_port: int, via_transport: str) -> bytes:
    return lf2crlf(
        f"""SIP/2.0 200 OK
Via: SIP/2.0/{via_transport} 127.0.0.1:{via_port};branch=z9hG4bK1e5b2b763d
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

""".encode()
    )


class TestSocket:
    local_port: int
    remote_port: int

    def __init__(self, sock: socket.socket) -> None:
        self.local_port = sock.getsockname()[1]
        self.remote_port = sock.getpeername()[1]
        self._sock = sock

    async def close(self) -> None:
        self._sock.close()

    async def recv(self) -> bytes:
        return self._sock.recv(2000)

    async def send(self, data: bytes) -> None:
        self._sock.send(data)
        await asyncio.sleep(0.1)


class TestWebsocket:
    local_port: int

    def __init__(self, sock: websockets.asyncio.connection.Connection) -> None:
        self.local_port = sock.local_address[1]
        self.remote_port = sock.remote_address[1]
        self._sock = sock

    async def close(self) -> None:
        await self._sock.close()

    async def recv(self) -> bytes:
        data = await self._sock.recv(decode=False)
        assert isinstance(data, bytes)
        return data

    async def send(self, data: bytes) -> None:
        await self._sock.send(data)
        await asyncio.sleep(0.1)


class BaseTestCase(unittest.TestCase):
    def assertMessage(self, message: sipmessage.Message, data: bytes) -> None:
        self.assertEqual(serialize_message(message), lf2crlf(data))

    @contextlib.asynccontextmanager
    async def transport_layer(
        self,
        listen_addresses: list[TransportAddress],
    ) -> AsyncGenerator[tuple[TransportLayer, list[sipmessage.Message]], None]:
        received: list[sipmessage.Message] = []

        async def message_handler(message: sipmessage.Message) -> None:
            received.append(message)

        transport = TransportLayer()
        transport.request_handler = message_handler
        transport.response_handler = message_handler
        try:
            for addr in listen_addresses:
                await transport.listen(addr)
            yield transport, received
        finally:
            await transport.close()


class NoTransportChannelTest(BaseTestCase):
    @asynctest
    async def test_handle_response_no_vias(self) -> None:
        response = parse_response(b"""SIP/2.0 200 OK
To: sip:+33233445566@127.0.0.1:5060
From: sip:+33122334455@127.0.0.1:43248;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 INVITE

""")
        async with self.transport_layer([]) as (transport, _received):
            with self.assertLogs() as cm:
                await transport._handle_message(response)
        self.assertEqual(
            cm.output,
            ["WARNING:sipua.transport:Expected exactly one Via header, got 0"],
        )

    @asynctest
    async def test_handle_response_too_many_vias(self) -> None:
        response = parse_response(b"""SIP/2.0 200 OK
Via: SIP/2.0/UDP 127.0.0.1:43248;branch=z9hG4bK1e5b2b763d
Via: SIP/2.0/UDP 127.0.0.1:1234;branch=z9hG4bKabcdefghij
To: sip:+33233445566@127.0.0.1:5060
From: sip:+33122334455@127.0.0.1:43248;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 INVITE

""")
        async with self.transport_layer([]) as (transport, _received):
            with self.assertLogs() as cm:
                await transport._handle_message(response)
        self.assertEqual(
            cm.output,
            ["WARNING:sipua.transport:Expected exactly one Via header, got 2"],
        )

    @asynctest
    async def test_send_request(self) -> None:
        async with self.transport_layer([]) as (transport, _received):
            request = create_request(uri_port=1234)
            with self.assertRaises(ConnectionError) as cm:
                await transport.send_message(request)
            self.assertEqual(str(cm.exception), "No suitable transport found")


class TcpTransportChannelTest(BaseTestCase):
    @contextlib.asynccontextmanager
    async def transport_layer_and_socket(
        self,
    ) -> AsyncGenerator[
        tuple[TransportLayer, TestSocket, list[sipmessage.Message]], None
    ]:
        async with self.transport_layer(
            [TransportAddress(protocol="tcp", host="127.0.0.1", port=5060)]
        ) as (transport, received):
            with socket.socket(type=socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                sock.connect(("127.0.0.1", 5060))
                yield (transport, TestSocket(sock), received)

    @asynctest
    async def test_receive_garbage(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            await sock.send(b"garbage")

            # Check no message was received.
            self.assertEqual(received, [])

            # Check the channel was closed.
            self.assertEqual(transport._channels, set())

    @asynctest
    async def test_receive_request_send_response(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            # Receive request.
            await sock.send(create_request_bytes(via_transport="TCP"))

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
                        transport="TCP",
                        host="1.2.3.4",
                        port=12345,
                        parameters=sipmessage.Parameters(
                            branch="z9hG4bK1e5b2b763d",
                            rport=str(sock.local_port),
                            received="127.0.0.1",
                        ),
                    )
                ],
            )

            # Send response.
            response = create_response(request=request, code=200)
            is_reliable = await transport.send_message(response)
            self.assertTrue(is_reliable)

            data = await sock.recv()
            self.assertEqual(
                data,
                lf2crlf(
                    f"""SIP/2.0 200 OK
Via: SIP/2.0/TCP 1.2.3.4:12345;branch=z9hG4bK1e5b2b763d;rport={sock.local_port};received=127.0.0.1
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

""".encode()
                ),
            )

    @asynctest
    async def test_send_request_and_receive_response(self) -> None:
        async with self.transport_layer(
            [TransportAddress(protocol="tcp", host="127.0.0.1", port=5060)]
        ) as (transport, received):
            with socket.socket(type=socket.SOCK_STREAM) as server_sock:
                server_sock.bind(("127.0.0.1", 0))
                server_sock.listen()

                # Send request.
                request = create_request(
                    uri_port=server_sock.getsockname()[1],
                    uri_transport="tcp",
                )
                await transport.send_message(request)

                sock = TestSocket(server_sock.accept()[0])
                data = await sock.recv()
                self.assertEqual(
                    data,
                    lf2crlf(
                        f"""OPTIONS sip:bob@127.0.0.1:{sock.local_port};transport=tcp SIP/2.0
Via: SIP/2.0/TCP 127.0.0.1:{sock.remote_port};branch=z9hG4bK1e5b2b763d
Max-Forwards: 70
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Contact: <sip:127.0.0.1:{sock.remote_port};transport=tcp>
Content-Length: 0

""".encode()
                    ),
                )

                # Receive response.
                await sock.send(
                    create_response_bytes(
                        via_port=sock.remote_port, via_transport="TCP"
                    )
                )

                self.assertEqual(len(received), 1)
                response = received[0]
                assert isinstance(response, sipmessage.Response)
                self.assertEqual(response.code, 200)
                self.assertEqual(response.phrase, "OK")

                await sock.close()

    @asynctest
    async def test_connect_fails(self) -> None:
        async with (
            self.transport_layer(
                [TransportAddress(protocol="tcp", host="127.0.0.1", port=5060)]
            ) as (transport, received),
        ):
            # Client sends request.
            request = create_request(uri_port=5080, uri_transport="tcp")
            with self.assertRaises(ConnectionRefusedError):
                await transport.send_message(request)


class UdpTransportChannelTest(BaseTestCase):
    @contextlib.asynccontextmanager
    async def transport_layer_and_socket(
        self,
    ) -> AsyncGenerator[
        tuple[TransportLayer, TestSocket, list[sipmessage.Message]], None
    ]:
        async with self.transport_layer(
            [TransportAddress(protocol="udp", host="127.0.0.1", port=5060)]
        ) as (transport, received):
            with socket.socket(type=socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                sock.connect(("127.0.0.1", 5060))
                yield (transport, TestSocket(sock), received)

    @asynctest
    async def test_receive_garbage(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            await sock.send(b"garbage")

            # Check no message was received.
            self.assertEqual(received, [])

            # Check the channel was not closed.
            self.assertEqual(len(transport._channels), 1)

    @asynctest
    async def test_receive_request_send_response(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            # Receive request.
            await sock.send(create_request_bytes(via_transport="UDP"))

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
                            rport=str(sock.local_port),
                            received="127.0.0.1",
                        ),
                    )
                ],
            )

            # Send response.
            response = create_response(request=request, code=200)
            is_reliable = await transport.send_message(response)
            self.assertFalse(is_reliable)

            data = await sock.recv()
            self.assertEqual(
                data,
                lf2crlf(
                    f"""SIP/2.0 200 OK
Via: SIP/2.0/UDP 1.2.3.4:12345;branch=z9hG4bK1e5b2b763d;rport={sock.local_port};received=127.0.0.1
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

""".encode()
                ),
            )

    @asynctest
    async def test_send_request_and_receive_response(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            # Send request.
            request = create_request(uri_port=sock.local_port)
            await transport.send_message(request)

            data = await sock.recv()
            self.assertEqual(
                data,
                lf2crlf(
                    f"""OPTIONS sip:bob@127.0.0.1:{sock.local_port} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1e5b2b763d
Max-Forwards: 70
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Contact: <sip:127.0.0.1:5060;transport=udp>
Content-Length: 0

""".encode()
                ),
            )

            # Receive response.
            await sock.send(create_response_bytes(via_port=5060, via_transport="UDP"))

            self.assertEqual(len(received), 1)
            response = received[0]
            assert isinstance(response, sipmessage.Response)
            self.assertEqual(response.code, 200)
            self.assertEqual(response.phrase, "OK")


class WebsocketTransportChannelTest(BaseTestCase):
    @contextlib.asynccontextmanager
    async def transport_layer_and_socket(
        self,
    ) -> AsyncGenerator[
        tuple[
            TransportLayer,
            TestWebsocket,
            list[sipmessage.Message],
        ],
        None,
    ]:
        async with self.transport_layer(
            [TransportAddress(protocol="ws", host="127.0.0.1", port=5080)]
        ) as (transport, received):
            async with websockets.asyncio.client.connect(
                "ws://127.0.0.1:5080", subprotocols=[WEBSOCKET_SUBPROTOCOL]
            ) as websocket:
                yield (transport, TestWebsocket(websocket), received)

    @asynctest
    async def test_receive_garbage(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            await sock.send(b"garbage")

            # Check no message was received.
            self.assertEqual(received, [])

            # Check the connection was not closed.
            self.assertEqual(len(transport._channels), 1)

    @asynctest
    async def test_receive_request_send_response(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            # Receive request.
            await sock.send(
                create_request_bytes(
                    via_addr="li62vs2t75f6.invalid", via_transport="WS"
                )
            )

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
                        transport="WS",
                        host="li62vs2t75f6.invalid",
                        parameters=sipmessage.Parameters(
                            branch="z9hG4bK1e5b2b763d",
                            rport=str(sock.local_port),
                            received="127.0.0.1",
                        ),
                    )
                ],
            )

            # Send response.
            response = create_response(request=request, code=200)
            is_reliable = await transport.send_message(response)
            self.assertTrue(is_reliable)

            data = await sock.recv()
            self.assertEqual(
                data,
                lf2crlf(
                    f"""SIP/2.0 200 OK
Via: SIP/2.0/WS li62vs2t75f6.invalid;branch=z9hG4bK1e5b2b763d;rport={sock.local_port};received=127.0.0.1
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Content-Length: 0

""".encode()
                ),
            )

    @asynctest
    @patch("sipua.transport.random_string", new=lambda x: "WeNzcJ9a6ATr")  # type: ignore
    async def test_send_request_and_receive_response(self) -> None:
        async with self.transport_layer_and_socket() as (transport, sock, received):
            # Send request.
            request = create_request(uri_port=sock.local_port, uri_transport="ws")
            await transport.send_message(request)

            data = await sock.recv()
            self.assertEqual(
                data,
                lf2crlf(
                    f"""OPTIONS sip:bob@127.0.0.1:{sock.local_port};transport=ws SIP/2.0
Via: SIP/2.0/WS WeNzcJ9a6ATr.invalid;branch=z9hG4bK1e5b2b763d
Max-Forwards: 70
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=7bc759c98ae3e112
Call-ID: 126a8db08eba7fb6
CSeq: 1 OPTIONS
Contact: <sip:WeNzcJ9a6ATr.invalid;transport=ws>
Content-Length: 0

""".encode()
                ),
            )

            # Receive response.
            await sock.send(create_response_bytes(via_port=5060, via_transport="UDP"))

            self.assertEqual(len(received), 1)
            response = received[0]
            assert isinstance(response, sipmessage.Response)
            self.assertEqual(response.code, 200)
            self.assertEqual(response.phrase, "OK")

    @asynctest
    async def test_connect_websocket(self) -> None:
        async with (
            self.transport_layer(
                [TransportAddress(protocol="ws", host="127.0.0.1", port=5080)]
            ) as (server_transport, server_received),
            self.transport_layer([]) as (client_transport, client_received),
        ):
            await client_transport.connect_websocket("ws://127.0.0.1:5080")

            # Client sends request.
            request = create_request(uri_port=5080, uri_transport="ws")
            await client_transport.send_message(request)
            await asyncio.sleep(0.1)

            self.assertEqual(len(server_received), 1)
            received_request = server_received[0]
            assert isinstance(received_request, sipmessage.Request)

            # Server sends reply.
            response = create_response(request=received_request, code=200)
            await server_transport.send_message(response)
            await asyncio.sleep(0.1)

            self.assertEqual(len(client_received), 1)
            client_response = client_received[0]
            assert isinstance(client_response, sipmessage.Response)


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
