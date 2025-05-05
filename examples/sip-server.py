#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import argparse
import asyncio
import logging

import sipmessage
import sipua


class SipServer(sipua.Application):
    async def handle_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request outside a dialog.
        """
        if request.method == "INVITE":
            # Accept the incoming call.
            call = sipua.Call.create_uas(
                dialog_layer=self.dialog_layer,
                request=request,
            )
            await call.accept(request)
        else:
            # Reject any other requests.
            await super().handle_request(request)


async def main() -> None:
    parser = argparse.ArgumentParser("sip server")
    parser.add_argument("--local-host", type=str, default="127.0.0.1")
    parser.add_argument("--local-port", type=int, default=5060)
    options = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    server = SipServer()
    await server.listen(
        sipua.TransportAddress("udp", options.local_host, options.local_port)
    )
    try:
        await asyncio.Future()
    finally:
        await server.close()


if __name__ == "__main__":
    asyncio.run(main())
