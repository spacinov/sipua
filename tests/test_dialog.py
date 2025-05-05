#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#


import contextlib
import functools
import unittest
from collections.abc import AsyncGenerator

import sipmessage
import sipua

from .utils import asynctest

ALICE = sipmessage.Address(
    name="Alice",
    uri=sipmessage.URI(scheme="sip", user="alice", host="127.0.0.1", port=5061),
)
BOB = sipmessage.Address(
    name="Bob",
    uri=sipmessage.URI(scheme="sip", user="bob", host="127.0.0.1", port=5062),
)


class DialogTest(unittest.TestCase):
    @contextlib.asynccontextmanager
    async def client_and_server(
        self,
    ) -> AsyncGenerator[tuple[sipua.DialogLayer, sipua.DialogLayer], None]:
        client_transport = sipua.TransportLayer()
        client_transaction = sipua.TransactionLayer(client_transport)
        client_dialog = sipua.DialogLayer(client_transaction)

        server_transport = sipua.TransportLayer()
        server_transaction = sipua.TransactionLayer(server_transport)
        server_dialog = sipua.DialogLayer(server_transaction)

        try:
            await client_transport.listen(
                sipua.TransportAddress("udp", "127.0.0.1", 5061)
            )
            await server_transport.listen(
                sipua.TransportAddress("udp", "127.0.0.1", 5062)
            )
            yield (client_dialog, server_dialog)
        finally:
            await client_transport.close()
            await server_transport.close()

    async def server_request_handler(
        self,
        request: sipmessage.Request,
        *,
        dialog_layer: sipua.DialogLayer,
        route_set: list[sipmessage.Address] = [],
    ) -> None:
        self.assertEqual(request.method, "INVITE")

        # Server creates dialog and responds 200.
        server_dialog = sipua.Dialog.create_uas(
            dialog_layer=dialog_layer, request=request
        )
        response = server_dialog.create_response(request, 200)
        self.assertEqual(response.call_id, request.call_id)
        self.assertEqual(response.cseq, request.cseq)
        self.assertEqual(response.from_address, request.from_address)
        self.assertEqual(response.via, request.via)
        transaction_layer = dialog_layer._transaction_layer
        await transaction_layer.send_response(response)

        # Check server dialog state.
        self.assertEqual(server_dialog.local_cseq, 1)
        self.assertEqual(server_dialog.remote_address, request.from_address)
        self.assertEqual(server_dialog.route_set, route_set)

    @asynctest
    async def test_invite(self) -> None:
        async with self.client_and_server() as (client, server):
            server.request_handler = functools.partial(
                self.server_request_handler, dialog_layer=server
            )

            # Client sends INVITE, server responds 200.
            client_dialog = sipua.Dialog.create_uac(
                dialog_layer=client,
                local_address=ALICE,
                remote_address=BOB,
            )
            request = client_dialog.create_request("INVITE")
            self.assertEqual(request.cseq, sipmessage.CSeq(sequence=1, method="INVITE"))
            response = await client_dialog.send_request(request)
            self.assertEqual(response.code, 200)

            # Check client dialog state.
            self.assertEqual(client_dialog.local_cseq, 2)
            self.assertEqual(client_dialog.remote_address, response.to_address)
            self.assertEqual(client_dialog.route_set, [])

            # Client sends BYE, server responds 501.
            request = client_dialog.create_request("BYE")
            response = await client_dialog.send_request(request)
            self.assertEqual(response.code, 501)
