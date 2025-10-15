#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import dataclasses
import typing

import sipmessage

from .transaction import TransactionLayer
from .transport import RequestHandler
from .utils import (
    create_contact,
    create_response,
    create_via,
    random_string,
    response_establishes_dialog,
)

DialogKey = tuple[str, str]

# When we drop support for Python 3.10, we can use `typing.Self`.
T = typing.TypeVar("T", bound="Dialog")


def get_dialog_key(request: sipmessage.Request) -> DialogKey:
    call_id = request.call_id or ""
    tag = request.to_address.parameters.get("tag") or ""
    return (call_id, tag)


def replace_tag(address: sipmessage.Address, tag: str) -> sipmessage.Address:
    return dataclasses.replace(
        address,
        parameters=address.parameters.replace(tag=tag),
    )


class Dialog:
    """
    A SIP dialog, representing a peer-to-peer SIP relationship between two
    user agents that persists for some time.

    See :rfc:`3261#section-12`.
    """

    def __init__(
        self,
        *,
        call_id: str,
        dialog_layer: "DialogLayer",
        local_address: sipmessage.Address,
        remote_address: sipmessage.Address,
        remote_uri: sipmessage.URI,
        route_set: list[sipmessage.Address] = [],
    ) -> None:
        self.call_id = call_id
        self._dialog_layer = dialog_layer
        # Set the tag for the local address unless we were given one.
        local_tag = local_address.parameters.get("tag")
        if local_tag is None:
            local_tag = random_string(10)
            self.local_address = replace_tag(local_address, local_tag)
        self.local_cseq = 1
        self.remote_address = remote_address
        self.remote_uri = remote_uri
        self.route_set = route_set
        self._key = (self.call_id, local_tag)

        # Register the dialog.
        dialog_layer._dialogs[self._key] = self

    @classmethod
    def create_uac(
        cls: typing.Type[T],
        *,
        dialog_layer: "DialogLayer",
        local_address: sipmessage.Address,
        remote_address: sipmessage.Address,
        route_set: list[sipmessage.Address] = [],
        **kwargs: object,
    ) -> T:
        """
        Create a client dialog.

        The initial request will neeed to be constructed using :meth:`create_request`.
        """
        return cls(
            call_id=random_string(22),
            dialog_layer=dialog_layer,
            local_address=local_address,
            remote_address=remote_address,
            remote_uri=remote_address.uri,
            route_set=route_set,
            **kwargs,
        )

    @classmethod
    def create_uas(
        cls: typing.Type[T],
        *,
        dialog_layer: "DialogLayer",
        request: sipmessage.Request,
        **kwargs: object,
    ) -> T:
        """
        Create a server dialog based on a received request.
        """
        return cls(
            call_id=request.call_id,
            dialog_layer=dialog_layer,
            local_address=request.to_address,
            remote_address=request.from_address,
            # The target for subsequent requests is given in the Contact header.
            remote_uri=request.contact[0].uri,
            # Populate the route set from the Record-Route headers.
            route_set=request.record_route,
            **kwargs,
        )

    def create_request(self, method: str) -> sipmessage.Request:
        """
        Create a new request for this dialog.
        """
        request = sipmessage.Request(method, self.remote_address.uri)
        request.via = [create_via()]
        request.max_forwards = 70
        request.to_address = self.remote_address
        request.from_address = self.local_address
        request.call_id = self.call_id
        request.cseq = sipmessage.CSeq(sequence=self.local_cseq, method=method)
        request.contact = [create_contact()]
        request.route = self.route_set
        self.local_cseq += 1
        return request

    def create_response(
        self, request: sipmessage.Request, code: int
    ) -> sipmessage.Response:
        """
        Create a response to the given request.
        """
        response = create_response(request=request, code=code)
        if response_establishes_dialog(request.method, code):
            response.to_address = self.local_address
            response.contact = [create_contact()]
        return response

    async def handle_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request for this dialog.

        This needs to be overriden as the base implementation replies
        with a "Not Implemented" error.
        """
        response = self.create_response(request, 501)
        await self.send_response(response)

    async def send_request(self, request: sipmessage.Request) -> sipmessage.Response:
        """
        Send the request in a transaction and return the final response.
        """
        response = await self._dialog_layer._transaction_layer.send_request(request)

        # See https://datatracker.ietf.org/doc/html/rfc3261#section-12.1.2
        if response_establishes_dialog(response.cseq.method, response.code):
            # Set the tag for the remote address.
            tag = response.to_address.parameters["tag"]
            assert isinstance(tag, str)
            self.remote_address = replace_tag(self.remote_address, tag)

            # Update the remote URI for subsequent requests.
            self.remote_uri = response.contact[0].uri

            # Populate the route set from the Record-Route headers taken
            # in reverse order.
            self.route_set = list(reversed(response.record_route))

        return response

    async def send_response(self, response: sipmessage.Response) -> None:
        """
        Send the response.
        """
        await self._dialog_layer._transaction_layer.send_response(response)


class DialogLayer:
    """
    SIP transaction layer.

    See :rfc:`3261#section-12`.
    """

    def __init__(self, transaction_layer: TransactionLayer) -> None:
        self._dialogs: dict[DialogKey, Dialog] = {}
        self._transaction_layer = transaction_layer
        self._transaction_layer.request_handler = self._handle_request

        #: A coroutine which will be called whenever a request is received
        #: which does not match an existing dialog.
        self.request_handler: RequestHandler | None = None

    async def _handle_request(self, request: sipmessage.Request) -> None:
        # Deliver the request to the dialog or the application.
        key = get_dialog_key(request)
        dialog = self._dialogs.get(key)
        if dialog is not None:
            await dialog.handle_request(request)
        elif self.request_handler is not None:
            await self.request_handler(request)

    def _dialog_terminated(self, dialog: Dialog) -> None:
        self._dialogs.pop(dialog._key)
