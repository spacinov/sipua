#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import asyncio
import contextlib
import functools
import typing
import unittest
from collections.abc import AsyncGenerator, Callable
from unittest.mock import patch

import sipmessage
import sipua.transaction as sip_transaction
from sipua.transaction import (
    ClientInviteTransaction,
    ClientNonInviteTransaction,
    ServerInviteTransaction,
    ServerNonInviteTransaction,
    TransactionLayer,
    TransactionState,
    get_client_transaction_key,
)
from sipua.transport import TransportAddress, TransportChannel, TransportLayer
from sipua.utils import ANY_HOST, ANY_PORT, create_response

from .utils import asynctest

P = typing.ParamSpec("P")
T = typing.TypeVar("T")

FROM_ADDRESS = sipmessage.Address(
    uri=sipmessage.URI(scheme="sip", user="alice", host="127.0.0.1", port=5061)
)
TO_ADDRESS = sipmessage.Address(
    uri=sipmessage.URI(scheme="sip", user="bob", host="127.0.0.1", port=5062)
)


class DummyTransportChannel(TransportChannel):
    is_reliable = False
    remote_address = TransportAddress(
        protocol="udp",
        host=ANY_HOST,
        port=ANY_PORT,
    )
    uri_transport = "udp"
    via_transport = "UDP"

    def __init__(self, outbox: list[sipmessage.Message]) -> None:
        self._outbox = outbox

    async def close(self) -> None:
        pass

    async def send_message(
        self, message: sipmessage.Message, destination: TransportAddress
    ) -> None:
        self._outbox.append(message)


def create_request(method: str, sequence: int = 1) -> sipmessage.Request:
    request = sipmessage.Request(method, TO_ADDRESS.uri)
    request.call_id = "12345"
    request.cseq = sipmessage.CSeq(sequence=sequence, method=method)
    request.from_address = FROM_ADDRESS
    request.to_address = TO_ADDRESS
    request.via = [
        sipmessage.Via(
            transport="UDP",
            host="127.0.0.1",
            port=5061,
            parameters=sipmessage.Parameters(branch="z9hG4bK1e5b2b763d"),
        )
    ]
    return request


def shorten_timers(func: Callable[P, T]) -> Callable[P, T]:
    """
    Reduce transaction timers by 100.
    """
    return patch("sipua.transaction.T1", sip_transaction.T1 / 100)(
        patch("sipua.transaction.T2", sip_transaction.T2 / 100)(
            patch("sipua.transaction.T4", sip_transaction.T4 / 100)(
                patch("sipua.transaction.TIMER_D", sip_transaction.TIMER_D / 100)(func)
            )
        )
    )


class BaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.message_outbox: list[sipmessage.Message] = []
        self.transport = TransportLayer()
        self.transport._channels.add(DummyTransportChannel(self.message_outbox))
        self.transaction_layer = TransactionLayer(transport_layer=self.transport)

    def assertSentRequests(self, methods: list[str]) -> None:
        sent_methods = [
            m.method for m in self.message_outbox if isinstance(m, sipmessage.Request)
        ]
        self.assertEqual(sent_methods[0 : len(methods)], methods)

    def assertSentResponses(self, codes: list[int]) -> None:
        sent_codes = [
            m.code for m in self.message_outbox if isinstance(m, sipmessage.Response)
        ]
        self.assertEqual(sent_codes[0 : len(codes)], codes)

    async def receive_messages(self, *messages: sipmessage.Message) -> None:
        for message in messages:
            if isinstance(message, sipmessage.Request):
                await self.transaction_layer._receive_request(message)
            elif isinstance(message, sipmessage.Response):
                await self.transaction_layer._receive_response(message)


class ClientInviteTransactionTest(BaseTestCase):
    def create_transaction(
        self, request: sipmessage.Request
    ) -> ClientInviteTransaction:
        transaction = ClientInviteTransaction(
            request=request, transaction_layer=self.transaction_layer
        )
        self.assertEqual(transaction._state, TransactionState.Calling)
        key = get_client_transaction_key(request)
        self.transaction_layer._client_transactions[key] = transaction
        return transaction

    @asynctest
    async def test_response_200(self) -> None:
        request = create_request("INVITE")
        response_100 = create_response(request=request, code=100)
        response_200 = create_response(request=request, code=200)

        transaction = self.create_transaction(request)

        result = await asyncio.gather(
            transaction.run(),
            self.receive_messages(response_100, response_200),
        )
        self.assertEqual(result, [response_200, None])
        self.assertEqual(transaction._state, TransactionState.Terminated)
        self.assertSentRequests(["INVITE", "ACK"])

    @asynctest
    @shorten_timers
    async def test_response_404(self) -> None:
        request = create_request("INVITE")
        response_404 = create_response(request=request, code=404)

        transaction = self.create_transaction(request)

        result = await asyncio.gather(
            transaction.run(),
            self.receive_messages(response_404),
        )
        self.assertEqual(result, [response_404, None])
        self.assertEqual(transaction._state, TransactionState.Completed)
        self.assertSentRequests(["INVITE", "ACK"])

        # Allow timer D to expire.
        await asyncio.sleep(sip_transaction.TIMER_D)
        self.assertEqual(transaction._state, TransactionState.Terminated)

    @asynctest
    @shorten_timers
    async def test_timeout(self) -> None:
        request = create_request("INVITE")

        transaction = self.create_transaction(request)

        with self.assertRaises(TimeoutError):
            await transaction.run()
        self.assertEqual(transaction._state, TransactionState.Terminated)
        self.assertSentRequests(
            ["INVITE", "INVITE", "INVITE", "INVITE", "INVITE", "INVITE", "INVITE"]
        )


class ClientNonInviteTransactionTest(BaseTestCase):
    def create_transaction(
        self, request: sipmessage.Request
    ) -> ClientNonInviteTransaction:
        transaction = ClientNonInviteTransaction(
            request=request, transaction_layer=self.transaction_layer
        )
        self.assertEqual(transaction._state, TransactionState.Trying)
        key = get_client_transaction_key(request)
        self.transaction_layer._client_transactions[key] = transaction
        return transaction

    @asynctest
    async def test_response_200(self) -> None:
        request = create_request("REGISTER")
        response_100 = create_response(request=request, code=100)
        response_200 = create_response(request=request, code=200)

        transaction = self.create_transaction(request)

        result = await asyncio.gather(
            transaction.run(),
            self.receive_messages(response_100, response_200),
        )
        self.assertEqual(result, [response_200, None])
        self.assertEqual(transaction._state, TransactionState.Completed)
        self.assertSentRequests(["REGISTER"])

    @asynctest
    @shorten_timers
    async def test_response_404(self) -> None:
        request = create_request("REGISTER")
        response_404 = create_response(request=request, code=404)

        transaction = self.create_transaction(request)

        result = await asyncio.gather(
            transaction.run(),
            self.receive_messages(response_404),
        )
        self.assertEqual(result, [response_404, None])
        self.assertEqual(transaction._state, TransactionState.Completed)
        self.assertSentRequests(["REGISTER"])

        # Allow timer K to expire.
        await asyncio.sleep(sip_transaction.T4)
        self.assertEqual(transaction._state, TransactionState.Terminated)

    @asynctest
    @shorten_timers
    async def test_timeout(self) -> None:
        request = create_request("REGISTER")

        transaction = self.create_transaction(request)

        with self.assertRaises(TimeoutError):
            await transaction.run()
        self.assertEqual(transaction._state, TransactionState.Terminated)
        self.assertSentRequests(
            [
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
                "REGISTER",
            ]
        )


class ServerInviteTransactionTest(BaseTestCase):
    async def create_transaction(
        self, request: sipmessage.Request
    ) -> ServerInviteTransaction:
        await self.transaction_layer._receive_request(request)

        transactions = list(self.transaction_layer._server_transactions.values())
        self.assertEqual(len(transactions), 1)

        transaction = transactions[0]
        assert isinstance(transaction, ServerInviteTransaction)
        self.assertEqual(transaction._state, TransactionState.Proceeding)

        return transaction

    @asynctest
    @shorten_timers
    async def test_response_200(self) -> None:
        request = create_request("INVITE")
        transaction = await self.create_transaction(request)

        response = create_response(request=request, code=200)
        await transaction.send_response(response)
        self.assertEqual(transaction._state, TransactionState.Terminated)

        ack = create_request("ACK", sequence=2)
        await self.receive_messages(ack)
        self.assertEqual(transaction._state, TransactionState.Terminated)

        self.assertSentResponses([100, 200])

    @asynctest
    @shorten_timers
    async def test_response_404(self) -> None:
        request = create_request("INVITE")
        transaction = await self.create_transaction(request)

        response = create_response(request=request, code=404)
        await transaction.send_response(response)
        self.assertEqual(transaction._state, TransactionState.Completed)

        ack = create_request("ACK", sequence=2)
        await self.receive_messages(ack)
        self.assertEqual(transaction._state, TransactionState.Confirmed)

        # Allow timer I to expire.
        await asyncio.sleep(sip_transaction.T4)
        self.assertEqual(transaction._state, TransactionState.Terminated)

        self.assertSentResponses([100, 404])

    @asynctest
    @shorten_timers
    async def test_response_404_timeout(self) -> None:
        request = create_request("INVITE")
        transaction = await self.create_transaction(request)

        response = create_response(request=request, code=404)
        await transaction.send_response(response)
        self.assertEqual(transaction._state, TransactionState.Completed)

        # Allow timer G and H to expire.
        await asyncio.sleep(sip_transaction.T1 * 64)
        self.assertEqual(transaction._state, TransactionState.Terminated)

        self.assertSentResponses([100, 404, 404, 404, 404, 404, 404, 404, 404, 404])


class ServerNonInviteTransactionTest(BaseTestCase):
    async def create_transaction(
        self, request: sipmessage.Request
    ) -> ServerNonInviteTransaction:
        await self.transaction_layer._receive_request(request)

        transactions = list(self.transaction_layer._server_transactions.values())
        self.assertEqual(len(transactions), 1)

        transaction = transactions[0]
        assert isinstance(transaction, ServerNonInviteTransaction)
        self.assertEqual(transaction._state, TransactionState.Trying)

        return transaction

    @asynctest
    @shorten_timers
    async def test_response_100_then_200(self) -> None:
        request = create_request("REGISTER")
        transaction = await self.create_transaction(request)

        response = create_response(request=request, code=100)
        await transaction.send_response(response)
        self.assertEqual(transaction._state, TransactionState.Proceeding)

        response = create_response(request=request, code=200)
        await transaction.send_response(response)
        self.assertEqual(transaction._state, TransactionState.Completed)

        # Allow timer J to expire.
        await asyncio.sleep(sip_transaction.T1 * 64)
        self.assertEqual(transaction._state, TransactionState.Terminated)

        self.assertSentResponses([100, 200])

    @asynctest
    @shorten_timers
    async def test_response_200(self) -> None:
        request = create_request("REGISTER")
        transaction = await self.create_transaction(request)

        response = create_response(request=request, code=200)
        await transaction.send_response(response)
        self.assertEqual(transaction._state, TransactionState.Completed)

        # Allow timer J to expire.
        await asyncio.sleep(sip_transaction.T1 * 64)
        self.assertEqual(transaction._state, TransactionState.Terminated)

        self.assertSentResponses([200])


class EndToEndTest(unittest.TestCase):
    @contextlib.asynccontextmanager
    async def client_and_server(
        self,
    ) -> AsyncGenerator[tuple[TransactionLayer, TransactionLayer], None]:
        client_transport = TransportLayer()
        client_transaction = TransactionLayer(client_transport)

        server_transport = TransportLayer()
        server_transaction = TransactionLayer(server_transport)

        try:
            await client_transport.listen(TransportAddress("udp", "127.0.0.1", 5061))
            await server_transport.listen(TransportAddress("udp", "127.0.0.1", 5062))
            yield (client_transaction, server_transaction)
        finally:
            await client_transport.close()
            await server_transport.close()

    @asynctest
    async def test_invite(self) -> None:
        async def reply_to_invite(
            transaction_layer: TransactionLayer,
            request: sipmessage.Request,
        ) -> None:
            if request.method == "INVITE":
                response = create_response(request=request, code=200)
                await transaction_layer.send_response(response)

        async with self.client_and_server() as (client_transaction, server_transaction):
            server_transaction.request_handler = functools.partial(
                reply_to_invite, server_transaction
            )

            request = create_request("INVITE")
            response = await client_transaction.send_request(request)
            self.assertEqual(response.code, 200)

    @asynctest
    async def test_invite_connection_error(self) -> None:
        async with self.client_and_server() as (client_transaction, server_transaction):
            request = create_request("INVITE")
            request.uri = sipmessage.URI(
                scheme="sip",
                user="bob",
                host="127.0.0.1",
                port=1234,
                parameters=sipmessage.Parameters(transport="tcp"),
            )
            response = await client_transaction.send_request(request)
            self.assertEqual(response.code, 503)

    @asynctest
    @shorten_timers
    async def test_invite_timeout_error(self) -> None:
        async with self.client_and_server() as (client_transaction, server_transaction):
            await server_transaction._transport_layer.close()

            request = create_request("INVITE")
            response = await client_transaction.send_request(request)
            self.assertEqual(response.code, 408)

    @asynctest
    async def test_register(self) -> None:
        async def reply_to_register(
            transaction_layer: TransactionLayer, request: sipmessage.Request
        ) -> None:
            if request.method == "REGISTER":
                response = create_response(request=request, code=200)
                await transaction_layer.send_response(response)

        async with self.client_and_server() as (client_transaction, server_transaction):
            server_transaction.request_handler = functools.partial(
                reply_to_register, server_transaction
            )

            request = create_request("REGISTER")
            response = await client_transaction.send_request(request)
            self.assertEqual(response.code, 200)
