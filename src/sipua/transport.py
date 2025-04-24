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

logger = logging.getLogger(__name__)

ConnectHandler = typing.Callable[["BaseTransport"], None]
DisconnectHandler = typing.Callable[["BaseTransport", Exception | None], None]
MessageHandler = typing.Callable[["BaseTransport", sipmessage.Message], None]

ANY_HOST = "any"
ANY_PORT = 0


@dataclasses.dataclass
class TransportAddress:
    protocol: str
    host: str
    port: int


class BaseTransport(abc.ABC):
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


def set_transport_source(message: sipmessage.Message, transport: BaseTransport) -> None:
    if isinstance(message, sipmessage.Request):
        # Rewrite the top-most Via with our address.
        vias = message.via
        if vias and vias[0].host == ANY_HOST:
            vias[0] = dataclasses.replace(
                vias[0],
                host=transport.via_host,
                port=transport.via_port,
                transport=transport.via_transport,
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
                    host=transport.via_host,
                    port=transport.via_port,
                    parameters=contact.uri.parameters.replace(
                        transport=transport.uri_transport
                    ),
                ),
            )
            contacts_changed = True
        contacts.append(contact)
    if contacts_changed:
        message.contact = contacts


def update_request_via(request: sipmessage.Request, host: str, port: int) -> None:
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
        if via.host != host:
            via = dataclasses.replace(
                via, parameters=via.parameters.replace(received=host)
            )
            via_changed = True

        # If the top-most `Via` contains an `rport` parameter with no value, set
        # the `rport` parameter to the port from which the request was received.
        #
        # https://datatracker.ietf.org/doc/html/rfc3581#section-4
        if "rport" in via.parameters and via.parameters["rport"] is None:
            via = dataclasses.replace(
                via, parameters=via.parameters.replace(rport=str(port))
            )
            via_changed = True

        if via_changed:
            request.via = [via] + request.via[1:]


class TransportLayer:
    """
    SIP transport layer.
    """

    def __init__(
        self,
        *,
        message_handler: typing.Callable[[sipmessage.Message], None],
    ) -> None:
        self._message_notifier = message_handler
        self._servers: set[asyncio.Server] = set()
        self._transports: set[BaseTransport] = set()

    async def close(self) -> None:
        """
        Close the transport layer.
        """
        # Iterate over a copy of the transports to allow changes
        # during iteration.
        for transport in set(self._transports):
            await transport.close()
        self._transports.clear()

        for server in set(self._servers):
            server.close()
        self._servers.clear()

    async def listen(self, address: TransportAddress) -> None:
        """
        Start listening on the given transport address.
        """
        loop = asyncio.get_running_loop()

        if address.protocol == "tcp":
            server = await loop.create_server(
                lambda: TcpTransport(
                    connect_handler=self._connect_handler,
                    disconnect_handler=self._disconnect_handler,
                    message_handler=self._message_handler,
                ),
                host=address.host,
                port=address.port,
            )
            self._servers.add(server)
        else:
            assert address.protocol == "udp"
            await loop.create_datagram_endpoint(
                lambda: UdpTransport(
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

        # Determine transport to use.
        transport = await self._acquire_transport(destination)

        # Rewrite references to our transport address.
        set_transport_source(message, transport)

        # Send the message and return whether a reliable transport was used.
        await transport.send_message(message, destination)
        return transport.is_reliable

    async def _acquire_transport(self, destination: TransportAddress) -> BaseTransport:
        """
        Find a suitable transport for the given destination.
        """
        for transport in self._transports:
            if (
                transport.remote_address is not None
                and transport.remote_address.protocol == destination.protocol
                and (transport.remote_address.host in (destination.host, ANY_HOST))
                and (transport.remote_address.port in (destination.port, ANY_PORT))
            ):
                return transport

        if destination.protocol == "tcp" and self._servers:
            loop = asyncio.get_running_loop()
            _transport, protocol = await loop.create_connection(
                lambda: TcpTransport(
                    connect_handler=self._connect_handler,
                    disconnect_handler=self._disconnect_handler,
                    message_handler=self._message_handler,
                ),
                host=destination.host,
                port=destination.port,
            )
            assert protocol in self._transports
            return protocol

        raise RuntimeError("No suitable transport found")

    def _connect_handler(self, transport: BaseTransport) -> None:
        self._transports.add(transport)

    def _disconnect_handler(
        self, transport: BaseTransport, exc: Exception | None
    ) -> None:
        self._transports.discard(transport)

    def _message_handler(
        self, _transport: BaseTransport, message: sipmessage.Message
    ) -> None:
        self._message_notifier(message)


class TcpTransport(BaseTransport, asyncio.Protocol):
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
        message_str = str(message)
        logger.info("=>\n\n" + message_str)

        if self._transport is not None:
            self._transport.write(message_str.encode("utf8"))

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
        message_str = data.decode("utf8")
        logger.info("<=\n\n" + message_str)

        try:
            message = sipmessage.Message.parse(message_str)
        except ValueError:
            # We cannot recover, close the socket.
            assert self._transport is not None
            self._transport.close()
            return
        else:
            if (
                isinstance(message, sipmessage.Request)
                and self.remote_address is not None
            ):
                update_request_via(
                    message, self.remote_address.host, self.remote_address.port
                )
            self._message_handler(self, message)


class UdpTransport(BaseTransport, asyncio.DatagramProtocol):
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
        message_str = str(message)
        logger.info("=>\n\n" + message_str)

        if self._transport is not None:
            addr = (destination.host, destination.port)
            self._transport.sendto(message_str.encode("utf8"), addr)

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
        message_str = data.decode("utf8")
        logger.info("<=\n\n" + message_str)

        try:
            message = sipmessage.Message.parse(message_str)
        except ValueError:
            # Ignore the datagram.
            return
        else:
            if isinstance(message, sipmessage.Request):
                update_request_via(message, addr[0], addr[1])
            self._message_handler(self, message)
