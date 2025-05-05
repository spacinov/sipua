#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import sipmessage

from .dialog import DialogLayer
from .transaction import TransactionLayer
from .transport import TransportAddress, TransportLayer
from .utils import create_response


class Application:
    """
    Convenience class to facilitate creating a SIP user agent.
    """

    def __init__(self) -> None:
        self.transport_layer = TransportLayer()
        self.transaction_layer = TransactionLayer(self.transport_layer)
        self.dialog_layer = DialogLayer(self.transaction_layer)
        self.dialog_layer.request_handler = self.handle_request

    async def close(self) -> None:
        """
        Close the transport layer.
        """
        await self.transport_layer.close()

    async def connect_websocket(self, addr: str) -> None:
        """
        Establish an outgoing WebSocket connection.
        """
        await self.transport_layer.connect_websocket(addr)

    async def listen(self, address: TransportAddress) -> None:
        """
        Start listening on given transport address.
        """
        await self.transport_layer.listen(address)

    # overrideable

    async def handle_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request which does not match an existing dialog.

        You can override this by subclassing :class:`Application`,
        for instance to handle incoming calls.
        """
        response = create_response(request=request, code=501)
        await self.transaction_layer.send_response(response)
