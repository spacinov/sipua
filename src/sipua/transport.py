#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import abc
import asyncio
import dataclasses
import ipaddress
import logging
import socket
import typing

import sipmessage
import websockets.asyncio.client
import websockets.asyncio.connection
import websockets.asyncio.server

from .utils import ANY_HOST, ANY_PORT, random_string

logger = logging.getLogger(__name__)

# Internal handlers.
ConnectHandler = typing.Callable[["TransportChannel"], None]
DisconnectHandler = typing.Callable[["TransportChannel", Exception | None], None]
MessageHandler = typing.Callable[["TransportChannel", sipmessage.Message], None]

# Public handlers.
RequestHandler = typing.Callable[
    [sipmessage.Request], typing.Coroutine[None, None, None]
]
ResponseHandler = typing.Callable[
    [sipmessage.Response], typing.Coroutine[None, None, None]
]

WEBSOCKET_SUBPROTOCOL = typing.cast(websockets.Subprotocol, "sip")


@dataclasses.dataclass
class TransportAddress:
    protocol: str
    'The protocol, e.g. `"udp"`, `"tcp"` or `"ws"`.'

    host: str
    'The transport host, e.g. `"127.0.0.1"`.'

    port: int
    "The transport port, e.g. `5060`."


class TransportChannel(abc.ABC):
    is_reliable: bool
    uri_transport: str
    remote_address: TransportAddress | None = None
    via_host: str
    via_port: int | None = None
    via_transport: str

    @abc.abstractmethod
    async def close(self) -> None: ...  # pragma: no cover

    @abc.abstractmethod
    async def send_message(
        self, message: sipmessage.Message, destination: TransportAddress
    ) -> None: ...  # pragma: no cover


def get_default_port(protocol: str) -> int:
    """
    Return the default port for the given protocol.
    """
    if protocol in ("ws", "wss"):
        return 0
    elif protocol == "tls":
        return 5061
    else:
        return 5060


async def get_transport_destination(message: sipmessage.Message) -> TransportAddress:
    """
    Determine the protocol, host and port to which a message should be sent.
    """
    protocol: str
    host: str
    port: int

    if isinstance(message, sipmessage.Request):
        # For requests, use the `Request-URI` or the first `Route` header.
        #
        # https://datatracker.ietf.org/doc/html/rfc3261#section-8.1.2
        route_set = message.route
        if route_set and "lr" in route_set[0].uri.parameters:
            # Loose routing, use the first `Route` header.
            uri = route_set[0].uri
        else:
            # Strict routing or empty route set, use the `Request-URI`.
            uri = message.uri

        # Check whether the target is a numeric IP address.
        try:
            ipaddress.ip_address(uri.host)
        except ValueError:
            is_ip_address = False
        else:
            is_ip_address = True

        # Select a transport protocol.
        #
        # As we do not support NAPTR lookups, we diverge from spec and
        # select either UDP or TLS depending on the the URI scheme.
        # This should theoretically only be done if the URI host is a
        # numeric IP address.
        #
        # https://datatracker.ietf.org/doc/html/rfc3263#section-4.1
        if "transport" in uri.parameters and uri.parameters["transport"]:
            # A transport was explicitly specified, use it.
            protocol = uri.parameters["transport"].lower()
        elif uri.scheme == "sips":
            # The URI scheme is "sips", use TLS.
            protocol = "tls"
        else:
            # Default to UDP.
            protocol = "udp"

        # Determine the IP address and port.
        #
        # https://datatracker.ietf.org/doc/html/rfc3263#section-4.2
        if is_ip_address or protocol == "ws":
            # The host is an IP address, use the specified port or the default
            # port for the transport protocol.
            #
            # We diverge from spec and also handle WebSockets here.
            host = uri.host
            port = uri.port or get_default_port(protocol)
        elif uri.port is not None:
            host = await asyncio.get_running_loop().run_in_executor(
                None, socket.gethostbyname, uri.host
            )
            port = uri.port
        else:
            raise NotImplementedError("SRV lookups are not yet supported")
    else:
        # For responses, use the top-most `Via` header.
        #
        # https://datatracker.ietf.org/doc/html/rfc3261#section-18.2.2
        via = message.via[0]

        # Select the transport protocol.
        protocol = via.transport.lower()

        # If the Via contains a "received" parameter, use it. Otherwise
        # use the "sent-by" value which is guaranteed to be an IP address.
        if "received" in via.parameters and via.parameters["received"]:
            host = via.parameters["received"]
        else:
            host = via.host

        # If the Via contains an "rport" parameter, use it. Otherwise use
        # the "sent-by value".
        if "rport" in via.parameters and via.parameters["rport"]:
            port = int(via.parameters["rport"])
        else:
            port = via.port or get_default_port(protocol)

    return TransportAddress(protocol=protocol, host=host, port=port)


def serialize_message(message: sipmessage.Message) -> bytes:
    """
    Serialise the message to bytes.

    This exists purely to keep type checks happy.
    """
    assert isinstance(message, (sipmessage.Request, sipmessage.Response))
    return bytes(message)


def set_transport_source(
    message: sipmessage.Message, channel: TransportChannel
) -> None:
    if isinstance(message, sipmessage.Request):
        # Rewrite the top-most Via with our address.
        vias = message.via
        if vias and vias[0].host == ANY_HOST:
            vias[0] = dataclasses.replace(
                vias[0],
                host=channel.via_host,
                port=channel.via_port,
                transport=channel.via_transport,
            )
            message.via = vias

    # Rewrite Contact headers with our address.
    contacts = []
    contacts_changed = False
    for contact in message.contact:
        if contact.uri.host == ANY_HOST:
            contact = dataclasses.replace(
                contact,
                uri=dataclasses.replace(
                    contact.uri,
                    host=channel.via_host,
                    port=channel.via_port,
                    parameters=contact.uri.parameters.replace(
                        transport=channel.uri_transport
                    ),
                ),
            )
            contacts_changed = True
        contacts.append(contact)
    if contacts_changed:
        message.contact = contacts


def update_request_via(
    request: sipmessage.Request, host: str, port: int, force: bool = False
) -> None:
    """
    Update the top-most `Via` header based on the IP address and port
    from which the request was received.
    """
    if request.via:
        via = request.via[0]
        via_changed = False

        # If the host portion of the `sent-by` in the top-most `Via` does
        # not match the IP address from which the request was received.
        #
        # https://datatracker.ietf.org/doc/html/rfc3261#section-18.2.1
        if force or via.host != host:
            via = dataclasses.replace(
                via, parameters=via.parameters.replace(received=host)
            )
            via_changed = True

        # If the top-most `Via` contains an `rport` parameter with no value, set
        # the `rport` parameter to the port from which the request was received.
        #
        # https://datatracker.ietf.org/doc/html/rfc3581#section-4
        if force or ("rport" in via.parameters and via.parameters["rport"] is None):
            via = dataclasses.replace(
                via, parameters=via.parameters.replace(rport=str(port))
            )
            via_changed = True

        if via_changed:
            request.via = [via] + request.via[1:]


class TransportLayer:
    """
    SIP transport layer which handles the transmission of requests and responses
    over network transports.

    See :rfc:`3261#section-18`.
    """

    def __init__(self) -> None:
        self._channels: set[TransportChannel] = set()
        self._tcp_servers: set[asyncio.Server] = set()
        self._ws_client = False
        self._ws_servers: set[websockets.asyncio.server.Server] = set()

        #: A coroutine which will be called whenever a request is received.
        self.request_handler: RequestHandler | None = None

        #: A coroutine which will be called whenever a response is received.
        self.response_handler: ResponseHandler | None = None

    async def close(self) -> None:
        """
        Close the transport layer.
        """
        for channel in set(self._channels):
            await channel.close()
        self._channels.clear()

        for tcp_server in self._tcp_servers:
            tcp_server.close()
        self._tcp_servers.clear()

        for ws_server in self._ws_servers:
            ws_server.close()
        self._ws_servers.clear()

    async def connect_websocket(self, uri: str) -> None:
        assert not self._channels, (
            "WebSocket client connection must be the only channel"
        )
        self._ws_client = True

        websocket = await websockets.asyncio.client.connect(
            uri, subprotocols=[WEBSOCKET_SUBPROTOCOL]
        )
        ready_event = asyncio.Event()
        asyncio.create_task(
            self._serve_websocket(
                is_secure=uri.startswith("wss:"),
                ready_event=ready_event,
                websocket=websocket,
            )
        )
        await ready_event.wait()

    async def listen(self, address: TransportAddress) -> None:
        """
        Start listening on the given transport address.
        """
        assert not self._ws_client, (
            "WebSocket client connection must be the only channel"
        )

        loop = asyncio.get_running_loop()
        if address.protocol == "tcp":
            tcp_server = await loop.create_server(
                lambda: TcpTransportChannel(
                    connect_handler=self._connect_handler,
                    disconnect_handler=self._disconnect_handler,
                    message_handler=self._message_handler,
                ),
                host=address.host,
                port=address.port,
            )
            self._tcp_servers.add(tcp_server)
        elif address.protocol == "ws":
            ws_server = await websockets.asyncio.server.serve(
                lambda websocket: self._serve_websocket(
                    is_secure=False, websocket=websocket
                ),
                address.host,
                address.port,
                subprotocols=[WEBSOCKET_SUBPROTOCOL],
            )
            self._ws_servers.add(ws_server)
        else:
            assert address.protocol == "udp"
            await loop.create_datagram_endpoint(
                lambda: UdpTransportChannel(
                    connect_handler=self._connect_handler,
                    disconnect_handler=self._disconnect_handler,
                    message_handler=self._message_handler,
                ),
                local_addr=(address.host, address.port),
            )

    async def send_message(self, message: sipmessage.Message) -> bool:
        """
        Send the given message and return whether the selected
        transport is reliable.
        """
        # Finalise the message.
        message.content_length = len(message.body)

        # Determine transport recipient.
        destination = await get_transport_destination(message)

        # Determine channel to use.
        channel = await self._acquire_channel(destination)

        # Rewrite references to our transport address.
        set_transport_source(message, channel)

        # Send the message and return whether a reliable transport was used.
        await channel.send_message(message, destination)
        return channel.is_reliable

    async def _acquire_channel(self, destination: TransportAddress) -> TransportChannel:
        """
        Find a suitable transport for the given destination.
        """
        for channel in self._channels:
            # A WebSocket client sends all its requests to the WebSocket server.
            if self._ws_client:
                return channel

            if (
                channel.remote_address is not None
                and channel.remote_address.protocol == destination.protocol
                and (channel.remote_address.host in (destination.host, ANY_HOST))
                and (channel.remote_address.port in (destination.port, ANY_PORT))
            ):
                return channel

        if destination.protocol == "tcp" and self._tcp_servers:
            loop = asyncio.get_running_loop()
            _transport, channel = await loop.create_connection(
                lambda: TcpTransportChannel(
                    connect_handler=self._connect_handler,
                    disconnect_handler=self._disconnect_handler,
                    message_handler=self._message_handler,
                ),
                host=destination.host,
                port=destination.port,
            )
            assert channel in self._channels
            return channel

        raise ConnectionError("No suitable transport found")

    async def _handle_message(self, message: sipmessage.Message) -> None:
        if isinstance(message, sipmessage.Request) and self.request_handler is not None:
            await self.request_handler(message)
        elif (
            isinstance(message, sipmessage.Response)
            and self.response_handler is not None
        ):
            # Check there is exactly one Via header, otherwise drop the response.
            #
            # https://datatracker.ietf.org/doc/html/rfc3261#section-8.1.3.3
            via_count = len(message.via)
            if via_count != 1:
                logger.warning(f"Expected exactly one Via header, got {via_count}")
                return
            await self.response_handler(message)

    def _connect_handler(self, channel: TransportChannel) -> None:
        self._channels.add(channel)

    def _disconnect_handler(
        self, channel: TransportChannel, exc: Exception | None
    ) -> None:
        self._channels.discard(channel)

    def _message_handler(
        self, channel: TransportChannel, message: sipmessage.Message
    ) -> None:
        asyncio.create_task(self._handle_message(message))

    async def _serve_websocket(
        self,
        *,
        is_secure: bool,
        websocket: websockets.asyncio.connection.Connection,
        ready_event: asyncio.Event | None = None,
    ) -> None:
        channel = WebsocketTransportChannel(
            is_secure=is_secure,
            message_handler=self._message_handler,
            websocket=websocket,
        )
        self._connect_handler(channel)
        if ready_event is not None:
            ready_event.set()
        try:
            async for data in websocket:
                if isinstance(data, bytes):
                    channel.message_received(data)
        finally:
            self._disconnect_handler(channel, None)


class TcpTransportChannel(TransportChannel, asyncio.Protocol):
    is_reliable = True
    uri_transport = "tcp"
    via_transport = "TCP"

    def __init__(
        self,
        *,
        connect_handler: ConnectHandler,
        disconnect_handler: DisconnectHandler,
        message_handler: MessageHandler,
    ) -> None:
        self._connect_handler = connect_handler
        self._disconnect_handler = disconnect_handler
        self._message_handler = message_handler
        self._transport: asyncio.Transport | None = None

    async def close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    async def send_message(
        self, message: sipmessage.Message, destination: TransportAddress
    ) -> None:
        data = serialize_message(message)
        logger.info("=>\n\n" + data.decode())

        if self._transport is not None:
            self._transport.write(data)

    # Protocol

    def connection_lost(self, exc: Exception | None) -> None:
        self._disconnect_handler(self, exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = typing.cast(asyncio.Transport, transport)

        sockname = transport.get_extra_info("sockname")
        self.via_host = sockname[0]
        self.via_port = sockname[1]

        peername = transport.get_extra_info("peername")
        self.remote_address = TransportAddress(
            protocol="tcp",
            host=peername[0],
            port=peername[1],
        )

        self._connect_handler(self)

    def data_received(self, data: bytes) -> None:
        logger.info("<=\n\n" + data.decode())

        try:
            message = sipmessage.Message.parse(data)
        except ValueError:
            # We cannot recover, close the socket.
            assert self._transport is not None
            self._transport.close()
            return
        else:
            if isinstance(message, sipmessage.Request):
                assert self.remote_address is not None
                update_request_via(
                    message, self.remote_address.host, self.remote_address.port
                )
            self._message_handler(self, message)


class UdpTransportChannel(TransportChannel, asyncio.DatagramProtocol):
    is_reliable = False
    remote_address = TransportAddress(
        protocol="udp",
        host=ANY_HOST,
        port=ANY_PORT,
    )
    uri_transport = "udp"
    via_transport = "UDP"

    def __init__(
        self,
        *,
        connect_handler: ConnectHandler,
        disconnect_handler: DisconnectHandler,
        message_handler: MessageHandler,
    ) -> None:
        self._connect_handler = connect_handler
        self._disconnect_handler = disconnect_handler
        self._message_handler = message_handler
        self._transport: asyncio.DatagramTransport | None = None

    async def close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    async def send_message(
        self, message: sipmessage.Message, destination: TransportAddress
    ) -> None:
        data = serialize_message(message)
        logger.info("=>\n\n" + data.decode())

        if self._transport is not None:
            addr = (destination.host, destination.port)
            self._transport.sendto(data, addr)

    # DatagramProtocol

    def connection_lost(self, exc: Exception | None) -> None:
        self._disconnect_handler(self, exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = typing.cast(asyncio.DatagramTransport, transport)

        sockname = transport.get_extra_info("sockname")
        self.via_host = sockname[0]
        self.via_port = sockname[1]

        self._connect_handler(self)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        logger.info("<=\n\n" + data.decode())

        try:
            message = sipmessage.Message.parse(data)
        except ValueError:
            # Ignore the datagram.
            return
        else:
            if isinstance(message, sipmessage.Request):
                update_request_via(message, addr[0], addr[1])
            self._message_handler(self, message)


class WebsocketTransportChannel(TransportChannel):
    is_reliable = True
    uri_transport = "ws"

    def __init__(
        self,
        *,
        is_secure: bool,
        message_handler: MessageHandler,
        websocket: websockets.asyncio.connection.Connection,
    ) -> None:
        self._message_handler = message_handler
        self._websocket = websocket
        self.remote_address = TransportAddress(
            protocol="ws",
            host=websocket.remote_address[0],
            port=websocket.remote_address[1],
        )
        self.via_host = random_string(12) + ".invalid"
        self.via_port = None
        self.via_transport = "WSS" if is_secure else "WS"

    async def close(self) -> None:
        await self._websocket.close()

    async def send_message(
        self, message: sipmessage.Message, destination: TransportAddress
    ) -> None:
        data = serialize_message(message)
        logger.info("=>\n\n" + data.decode())

        await self._websocket.send(data)

    # WebSocket.

    def message_received(self, data: bytes) -> None:
        logger.info("<=\n\n" + data.decode())

        try:
            message = sipmessage.Message.parse(data)
        except ValueError:
            # Discard invalid message.
            return
        else:
            if isinstance(message, sipmessage.Request):
                assert self.remote_address is not None
                update_request_via(
                    message,
                    self.remote_address.host,
                    self.remote_address.port,
                    force=True,
                )
            self._message_handler(self, message)
