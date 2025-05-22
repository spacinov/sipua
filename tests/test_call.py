#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#


import asyncio
import re
import unittest

import sipmessage
import sipua

from .utils import asynctest

UDP_CLIENT = sipua.TransportAddress("udp", "127.0.0.1", 5061)
UDP_SERVER = sipua.TransportAddress("udp", "127.0.0.1", 5060)


def strip_ice(sdp: str) -> str:
    return re.sub(
        r"^a=(candidate|end-of-candidates|ice-pwd|ice-ufrag).*\n",
        "",
        sdp,
        flags=re.M,
    )


class ClientApplication(sipua.Application):
    async def invite(
        self,
        *,
        local_address: sipmessage.Address,
        remote_address: sipmessage.Address,
        extra_headers: list[tuple[str, str]] = [],
        **kwargs: object,
    ) -> None:
        call = sipua.Call.create_uac(
            dialog_layer=self.dialog_layer,
            local_address=local_address,
            remote_address=remote_address,
            route_set=[],
            **kwargs,
        )
        assert call.audioTransceiver.kind == "audio"

        await call.invite(extra_headers=extra_headers)

        # send media
        await asyncio.sleep(2)

        # hangup
        await call.hangup()

        # hangup again
        await call.hangup()


class ServerApplication(sipua.Application):
    def __init__(self, dtls: bool = False, ice: bool = True) -> None:
        super().__init__()
        self.dtls = dtls
        self.ice = ice
        self.invite_headers: list[str] = []

    async def handle_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request outside a dialog.
        """
        if request.method == "INVITE":
            call = sipua.Call.create_uas(
                dialog_layer=self.dialog_layer,
                dtls=self.dtls,
                request=request,
            )

            # Optionally strip out ICE information from SDP to emulate
            # a peer which does not support ICE.
            if not self.ice:
                real_create_sdp = call._create_sdp
                real_handle_sdp = call._handle_sdp

                async def patched_create_sdp() -> str:
                    sdp = await real_create_sdp()
                    return strip_ice(sdp)

                async def patched_handle_sdp(sdp: str) -> None:
                    sdp = strip_ice(sdp)
                    await real_handle_sdp(sdp)

                call._create_sdp = patched_create_sdp  # type: ignore
                call._handle_sdp = patched_handle_sdp  # type: ignore

            # Send response.
            await call.accept(request)

            self.invite_headers = sorted(request.headers.keys())
        else:
            await super().handle_request(request)


class BaseTestCase(unittest.TestCase):
    def assertNoDialogs(self, app: sipua.Application) -> None:
        self.assertEqual(app.dialog_layer._dialogs, {})


class UdpTest(BaseTestCase):
    local_address = sipmessage.Address(
        name="Alice",
        uri=sipmessage.URI(
            scheme="sip",
            user="alice",
            host="127.0.0.1",
            port=5061,
        ),
    )
    remote_address = sipmessage.Address(
        name="Bob",
        uri=sipmessage.URI(
            scheme="sip",
            user="bob",
            host="127.0.0.1",
            port=5060,
        ),
    )

    @asynctest
    async def test_invite_ok(self) -> None:
        server = ServerApplication()
        await server.listen(UDP_SERVER)

        client = ClientApplication()
        await client.listen(UDP_CLIENT)
        await client.invite(
            local_address=self.local_address,
            remote_address=self.remote_address,
        )
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())

        self.assertEqual(
            server.invite_headers,
            [
                "CSeq",
                "Call-ID",
                "Contact",
                "Content-Length",
                "Content-Type",
                "From",
                "Max-Forwards",
                "To",
                "Via",
            ],
        )

    @asynctest
    async def test_invite_ok_no_ice(self) -> None:
        server = ServerApplication(ice=False)
        await server.listen(UDP_SERVER)

        client = ClientApplication()
        await client.listen(UDP_CLIENT)
        await client.invite(
            local_address=self.local_address,
            remote_address=self.remote_address,
        )
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())

    @asynctest
    async def test_invite_ok_with_dtls(self) -> None:
        server = ServerApplication(dtls=True)
        await server.listen(UDP_SERVER)

        client = ClientApplication()
        await client.listen(UDP_CLIENT)
        await client.invite(
            dtls=True,
            local_address=self.local_address,
            remote_address=self.remote_address,
        )
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())

    @asynctest
    async def test_invite_ok_with_extra_headers(self) -> None:
        server = ServerApplication(dtls=True)
        await server.listen(UDP_SERVER)

        client = ClientApplication()
        await client.listen(UDP_CLIENT)
        await client.invite(
            dtls=True,
            extra_headers=[
                ("X-Header-A", "value-a"),
                ("X-Header-B", "value-b1"),
                ("X-Header-B", "value-b2"),
            ],
            local_address=self.local_address,
            remote_address=self.remote_address,
        )
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())

        self.assertEqual(
            server.invite_headers,
            [
                "CSeq",
                "Call-ID",
                "Contact",
                "Content-Length",
                "Content-Type",
                "From",
                "Max-Forwards",
                "To",
                "Via",
                "X-Header-A",
                "X-Header-B",
            ],
        )

    @asynctest
    async def test_invite_ok_with_stun_server(self) -> None:
        server = ServerApplication()
        await server.listen(UDP_SERVER)

        client = ClientApplication()
        await client.listen(UDP_CLIENT)
        await client.invite(
            local_address=self.local_address,
            remote_address=self.remote_address,
            stun_server="stun:stun.l.google.com:19302",
        )
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())

    @asynctest
    async def test_invite_without_handler(self) -> None:
        server = sipua.Application()
        await server.listen(UDP_SERVER)

        client = ClientApplication()
        await client.listen(UDP_CLIENT)
        with self.assertRaises(Exception) as cm:
            await client.invite(
                local_address=self.local_address,
                remote_address=self.remote_address,
            )
        self.assertEqual(str(cm.exception), "Call failed: 501 Not Implemented")
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())


class WebSocketTest(BaseTestCase):
    local_address = sipmessage.Address(
        name="Alice",
        uri=sipmessage.URI(
            scheme="sip",
            user="alice",
            host="example.com",
            parameters=sipmessage.Parameters(transport="ws"),
        ),
    )
    remote_address = sipmessage.Address(
        name="Bob",
        uri=sipmessage.URI(
            scheme="sip",
            user="bob",
            host="example.com",
            parameters=sipmessage.Parameters(transport="ws"),
        ),
    )

    @asynctest
    async def test_invite_ok(self) -> None:
        server = ServerApplication(dtls=False)
        await server.listen(sipua.TransportAddress("ws", "127.0.0.1", 7443))

        client = ClientApplication()
        await client.connect_websocket("ws://127.0.0.1:7443")
        await client.invite(
            local_address=self.local_address,
            remote_address=self.remote_address,
        )
        self.assertNoDialogs(client)
        self.assertNoDialogs(server)

        await asyncio.gather(client.close(), server.close())
