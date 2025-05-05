#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import asyncio
import enum
import logging

import sipmessage

from .transport import RequestHandler, TransportLayer
from .utils import create_ack, create_response

logger = logging.getLogger(__name__)

T1 = 0.5
T2 = 4
T4 = 5

# Timer "D" is not defined relative to T1.
TIMER_D = 32

ClientTransactionKey = tuple[str, str]
ServerTransactionKey = tuple[str, str, str]


def get_client_transaction_key(message: sipmessage.Message) -> ClientTransactionKey:
    """
    Get the key used to match responses to client transactions.

    See :rfc:`3261#section-17.1.3`.
    """
    branch = message.via[0].parameters.get("branch")
    assert branch is not None, "Via branch must be defined for a transaction"

    if isinstance(message, sipmessage.Request):
        method = message.method
    else:
        method = message.cseq.method

    return (branch, method)


def get_server_transaction_key(message: sipmessage.Message) -> ServerTransactionKey:
    """
    Get the key used to match requests to server transactions.

    See :rfc:`3261#section-17.2.3`.
    """
    branch = message.via[0].parameters.get("branch")
    assert branch is not None, "Via branch must be defined for a transaction"

    sent_by = message.via[0].host
    if message.via[0].port is not None:
        sent_by += f":{message.via[0].port}"

    if isinstance(message, sipmessage.Request):
        if message.method == "ACK":
            method = "INVITE"
        else:
            method = message.method
    else:
        method = message.cseq.method

    return (branch, sent_by, method)


class TransactionState(enum.Enum):
    Trying = 0
    Calling = 1
    Proceeding = 2
    Completed = 3
    Confirmed = 4
    Terminated = 5


class Transaction:
    def __init__(
        self,
        *,
        request: sipmessage.Request,
        state: TransactionState,
        transaction_layer: "TransactionLayer",
    ) -> None:
        self._is_reliable = False
        self._request = request
        self._state = state
        self._transaction_layer = transaction_layer
        self._transport_layer = transaction_layer._transport_layer

    def _log_info(self, msg: str, *args: object) -> None:
        logger.info(
            self.__class__.__name__ + " (" + self._request.method + ") " + msg, *args
        )

    def _set_state(self, state: TransactionState) -> None:
        if state != self._state:
            self._log_info("%s -> %s", self._state, state)
            self._state = state
            if state == TransactionState.Terminated:
                self._transaction_layer._transaction_terminated(self)

    def _start_timer(self, name: str, delay: float) -> None:
        cb = getattr(self, "_timer_%s_expired" % name.lower())
        loop = asyncio.get_event_loop()

        def wrap_cb() -> None:
            self._log_info("timer %s expired" % name)
            cb()

        self._log_info("timer %s started %.1f s" % (name, delay))
        loop.call_later(delay, wrap_cb)


class TransactionLayer:
    """
    SIP transaction layer, which handles matching responses to requests,
    retransmissions and timeouts.

    See :rfc:`3261#section-17`.
    """

    def __init__(self, transport_layer: TransportLayer) -> None:
        transport_layer.request_handler = self._receive_request
        transport_layer.response_handler = self._receive_response

        self._client_transactions: dict[ClientTransactionKey, ClientTransaction] = {}
        self._server_transactions: dict[ServerTransactionKey, ServerTransaction] = {}
        self._transport_layer = transport_layer

        #: A coroutine which will be called whenever a request is received
        #: which creates a new server transaction.
        self.request_handler: RequestHandler | None = None

    async def send_request(self, request: sipmessage.Request) -> sipmessage.Response:
        """
        Send the request in a transaction and return the final response.

        If a fatal transport error occurs, a `503` response will be returned.

        If a timeout occurs, a `408` response will be returned.
        """
        key = get_client_transaction_key(request)
        assert key not in self._client_transactions, (
            "A client transaction was found for the request"
        )
        transaction: ClientInviteTransaction | ClientNonInviteTransaction
        if request.method == "INVITE":
            transaction = ClientInviteTransaction(
                request=request, transaction_layer=self
            )
        else:
            transaction = ClientNonInviteTransaction(
                request=request, transaction_layer=self
            )
        self._client_transactions[key] = transaction

        # Remap transport errors and timeouts to error responses.
        #
        # See https://datatracker.ietf.org/doc/html/rfc3261.html#section-8.1.3.1
        try:
            return await transaction.run()
        except ConnectionError:
            return create_response(request=request, code=503)
        except TimeoutError:
            return create_response(request=request, code=408)

    async def send_response(self, response: sipmessage.Response) -> None:
        """
        Send the response.
        """
        key = get_server_transaction_key(response)
        assert key in self._server_transactions, (
            "No server transaction was found for the response"
        )
        transaction = self._server_transactions[key]
        await transaction.send_response(response)

    async def _receive_request(self, request: sipmessage.Request) -> None:
        # Try matching the request to a server transaction.
        key = get_server_transaction_key(request)
        transaction = self._server_transactions.get(key)
        if transaction is not None:
            await transaction._receive_request(request)
            return
        elif request.method == "ACK":
            # An un-matched ACK means the transaction has
            # already been terminated.
            return

        # Create a new server transaction.
        if request.method == "INVITE":
            transaction = ServerInviteTransaction(
                request=request, transaction_layer=self
            )
        else:
            transaction = ServerNonInviteTransaction(
                request=request, transaction_layer=self
            )
        self._server_transactions[key] = transaction
        await transaction._receive_request(request)

        # Notify the transaction user.
        if self.request_handler is not None:
            await self.request_handler(request)

    async def _receive_response(self, response: sipmessage.Response) -> None:
        # Try matching the response to a client transaction.
        key = get_client_transaction_key(response)
        transaction = self._client_transactions.get(key)
        if transaction is not None:
            await transaction.receive_response(response)

    def _transaction_terminated(self, transaction: Transaction) -> None:
        if isinstance(
            transaction, (ClientInviteTransaction, ClientNonInviteTransaction)
        ):
            server_key = get_client_transaction_key(transaction._request)
            self._client_transactions.pop(server_key)
        elif isinstance(
            transaction, (ServerInviteTransaction, ServerNonInviteTransaction)
        ):
            client_key = get_server_transaction_key(transaction._request)
            self._server_transactions.pop(client_key)


class ClientInviteTransaction(Transaction):
    """
    An INVITE client transaction.

    See :rfc:`3261#section-17.1.2`.
    """

    def __init__(
        self, *, request: sipmessage.Request, transaction_layer: TransactionLayer
    ) -> None:
        assert request.method == "INVITE", "Invalid method"
        super().__init__(
            request=request,
            state=TransactionState.Calling,
            transaction_layer=transaction_layer,
        )
        self._future: asyncio.Future[sipmessage.Response] = asyncio.Future()

    async def receive_response(self, response: sipmessage.Response) -> None:
        """
        Handle a response from the transport layer.
        """
        if self._state in (TransactionState.Calling, TransactionState.Proceeding):
            if response.code >= 100 and response.code < 200:
                self._set_state(TransactionState.Proceeding)
            elif response.code >= 200 and response.code < 300:
                # Send ACK.
                ack = create_ack(request=self._request, response=response)
                await self._transport_layer.send_message(ack)

                self._set_state(TransactionState.Terminated)
                self._future.set_result(response)
            elif response.code >= 300 and response.code < 700:
                # Send ACK.
                ack = create_ack(request=self._request, response=response)
                await self._transport_layer.send_message(ack)

                self._set_state(TransactionState.Completed)
                self._future.set_result(response)

                self._start_timer("D", not self._is_reliable and TIMER_D or 0)

    async def run(self) -> sipmessage.Response:
        """
        Send the request and return the response. If no response is received, a
        :class:`TimeoutError` is raised.
        """

        self._is_reliable = await self._transport_layer.send_message(self._request)
        self._start_timer("B", 64 * T1)

        # For unreliable transports, schedule retransmission.
        if not self._is_reliable:
            self.__timer_a_value = T1
            self._start_timer("A", self.__timer_a_value)

        return await self._future

    def _timer_a_expired(self) -> None:
        """
        Re-transmit the request while the transaction is in the `Calling` state.

        This is only used for unreliable transports.
        """
        if self._state == TransactionState.Calling:
            asyncio.ensure_future(self._transport_layer.send_message(self._request))
            self.__timer_a_value *= 2
            self._start_timer("A", self.__timer_a_value)

    def _timer_b_expired(self) -> None:
        """
        Terminate the transaction if it is still in the `Calling` or `Proceeding`
        state.
        """
        if self._state in (TransactionState.Calling, TransactionState.Proceeding):
            self._set_state(TransactionState.Terminated)
            self._future.set_exception(TimeoutError)

    def _timer_d_expired(self) -> None:
        """
        Terminate the transaction after it reaches the `Completed` state.
        """
        if self._state == TransactionState.Completed:
            self._set_state(TransactionState.Terminated)


class ClientNonInviteTransaction(Transaction):
    """
    A non-INVITE client transaction.

    See :rfc:`3261#section-17.1.2`.
    """

    def __init__(
        self, *, request: sipmessage.Request, transaction_layer: TransactionLayer
    ) -> None:
        assert request.method != "INVITE", "Invalid method"
        super().__init__(
            request=request,
            state=TransactionState.Trying,
            transaction_layer=transaction_layer,
        )
        self._future: asyncio.Future[sipmessage.Response] = asyncio.Future()

    async def receive_response(self, response: sipmessage.Response) -> None:
        """
        Handle a response from the transport layer.
        """
        if self._state in (TransactionState.Trying, TransactionState.Proceeding):
            if response.code >= 100 and response.code < 200:
                self._set_state(TransactionState.Proceeding)
            elif response.code >= 200 and response.code < 700:
                self._set_state(TransactionState.Completed)
                self._future.set_result(response)

                self._start_timer("K", not self._is_reliable and T4 or 0)

    async def run(self) -> sipmessage.Response:
        """
        Send the request and return the response. If no response is received, a
        :class:`TimeoutError` is raised.
        """
        self._is_reliable = await self._transport_layer.send_message(self._request)
        self._start_timer("F", 64 * T1)

        # For unreliable transports, schedule retransmission.
        if not self._is_reliable:
            self.__timer_e_value = T1
            self._start_timer("E", self.__timer_e_value)

        return await self._future

    def _timer_e_expired(self) -> None:
        """
        Re-transmit the request while the transaction is in the `Trying` state.

        This is only used for unreliable transports.
        """
        if self._state == TransactionState.Trying:
            asyncio.ensure_future(self._transport_layer.send_message(self._request))
            self.__timer_e_value = min(2 * self.__timer_e_value, T2)
            self._start_timer("E", self.__timer_e_value)

    def _timer_f_expired(self) -> None:
        """
        Terminate the transaction if it is still in the `Trying` or `Proceeding`
        state.
        """
        if self._state in (TransactionState.Trying, TransactionState.Proceeding):
            self._set_state(TransactionState.Terminated)
            self._future.set_exception(TimeoutError)

    def _timer_k_expired(self) -> None:
        """
        Terminate the transaction after it reaches the `Completed` state.
        """
        if self._state == TransactionState.Completed:
            self._set_state(TransactionState.Terminated)


class ServerInviteTransaction(Transaction):
    """
    An INVITE server transaction.

    See :rfc:`3261#section-17.2.1`.
    """

    def __init__(
        self, *, request: sipmessage.Request, transaction_layer: TransactionLayer
    ) -> None:
        assert request.method == "INVITE", "Invalid method"
        super().__init__(
            request=request,
            state=TransactionState.Proceeding,
            transaction_layer=transaction_layer,
        )

    async def send_response(self, response: sipmessage.Response) -> None:
        """
        Send the given response.
        """
        if self._state == TransactionState.Proceeding:
            if response.code >= 100 and response.code < 200:
                self._is_reliable = await self._transport_layer.send_message(response)
            elif response.code >= 200 and response.code < 300:
                self._is_reliable = await self._transport_layer.send_message(response)
                self._set_state(TransactionState.Terminated)
            elif response.code >= 300 and response.code < 700:
                self._is_reliable = await self._transport_layer.send_message(response)
                self._set_state(TransactionState.Completed)
                self._start_timer("H", 64 * T1)

                # For unreliable transports, schedule retransmission.
                if not self._is_reliable:
                    self.response = response
                    self.__timer_g_value = T1
                    self._start_timer("G", self.__timer_g_value)

    async def _receive_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request from the transport layer.
        """
        if self._state == TransactionState.Proceeding and request.method == "INVITE":
            response = create_response(request=request, code=100)
            await self.send_response(response)
        elif self._state == TransactionState.Completed and request.method == "ACK":
            self._set_state(TransactionState.Confirmed)

            self._start_timer("I", not self._is_reliable and T4 or 0)

    def _timer_g_expired(self) -> None:
        """
        Re-transmit a 300-699 response while the transaction is in the `Completed`
        state.

        This is only used for unreliable transports.
        """
        if self._state == TransactionState.Completed:
            asyncio.ensure_future(self._transport_layer.send_message(self.response))
            self.__timer_g_value = min(2 * self.__timer_g_value, T2)
            self._start_timer("G", self.__timer_g_value)

    def _timer_h_expired(self) -> None:
        """
        Terminate the transaction after it reaches the `Completed` state.
        """
        if self._state == TransactionState.Completed:
            self._set_state(TransactionState.Terminated)

    def _timer_i_expired(self) -> None:
        """
        Terminate the transaction after it reaches the `Confirmed` state.
        """
        if self._state == TransactionState.Confirmed:
            self._set_state(TransactionState.Terminated)


class ServerNonInviteTransaction(Transaction):
    """
    A non-INVITE server transaction.

    See :rfc:`3261#section-17.2.2`.
    """

    def __init__(
        self, *, request: sipmessage.Request, transaction_layer: TransactionLayer
    ) -> None:
        assert request.method != "INVITE", "Invalid method"
        super().__init__(
            request=request,
            state=TransactionState.Trying,
            transaction_layer=transaction_layer,
        )

    async def send_response(self, response: sipmessage.Response) -> None:
        """
        Send the given response.
        """
        if self._state in (TransactionState.Trying, TransactionState.Proceeding):
            if response.code >= 100 and response.code < 200:
                self._is_reliable = await self._transport_layer.send_message(response)
                self._set_state(TransactionState.Proceeding)
            elif response.code >= 200 and response.code < 700:
                self._is_reliable = await self._transport_layer.send_message(response)
                self._set_state(TransactionState.Completed)

                self._start_timer("J", not self._is_reliable and 64 * T1 or 0)

    async def _receive_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request from the transport layer.
        """
        pass

    def _timer_j_expired(self) -> None:
        """
        Terminate the transaction after it reaches the `Completed` state.
        """
        if self._state == TransactionState.Completed:
            self._set_state(TransactionState.Terminated)


ClientTransaction = ClientInviteTransaction | ClientNonInviteTransaction
ServerTransaction = ServerInviteTransaction | ServerNonInviteTransaction
