#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import argparse
import asyncio
import logging

import sipmessage
import sipua


class SipClient(sipua.Application):
    async def invite(
        self,
        *,
        local_address: sipmessage.Address,
        remote_address: sipmessage.Address,
    ) -> None:
        # Make the call.
        call = sipua.Call.create_uac(
            dialog_layer=self.dialog_layer,
            local_address=local_address,
            remote_address=remote_address,
        )
        await call.invite()

        # Send media for a few seconds.
        await asyncio.sleep(5)

        # Hangup the call.
        await call.hangup()


async def main() -> None:
    parser = argparse.ArgumentParser("sip client")
    parser.add_argument("--local-username", type=str, default="+33122334455")
    parser.add_argument("--local-host", type=str, default="127.0.0.1")
    parser.add_argument("--local-port", type=int, default=5061)
    parser.add_argument("--remote-username", type=str, default="+33233445566")
    parser.add_argument("--remote-host", type=str, default="127.0.0.1")
    parser.add_argument("--remote-port", type=int, default=5060)
    options = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    app = SipClient()
    await app.listen(
        sipua.TransportAddress("udp", options.local_host, options.local_port)
    )
    await app.invite(
        local_address=sipmessage.Address(
            uri=sipmessage.URI(
                scheme="sip",
                user=options.local_username,
                host=options.local_host,
                port=options.local_port,
            )
        ),
        remote_address=sipmessage.Address(
            uri=sipmessage.URI(
                scheme="sip",
                user=options.remote_username,
                host=options.remote_host,
                port=options.remote_port,
            )
        ),
    )
    await app.close()
    await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
