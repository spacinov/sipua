#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import argparse
import asyncio
import logging

import sipmessage
import sipua
from aiortc.contrib.media import MediaBlackhole, MediaPlayer, MediaRecorder


async def ensure_hangup(
    call: sipua.Call, recorder: MediaBlackhole | MediaRecorder
) -> None:
    await asyncio.sleep(15)
    await call.hangup()
    await recorder.stop()


class SipServer(sipua.Application):
    def __init__(self, play_from: str, record_to: str) -> None:
        super().__init__()
        self.play_from = play_from
        self.record_to = record_to

    async def handle_request(self, request: sipmessage.Request) -> None:
        """
        Handle a request outside a dialog.
        """
        if request.method == "INVITE":
            call = sipua.Call.create_uas(
                dialog_layer=self.dialog_layer,
                request=request,
            )

            # Play audio from a file or fall back to a sine signal.
            if self.play_from:
                player = MediaPlayer(self.play_from)
            else:
                player = MediaPlayer(
                    "sine=frequency=440:sample_rate=48000:duration=1", format="lavfi"
                )
            call.audioTransceiver.sender.replaceTrack(player.audio)

            # Consume received audio.
            recorder: MediaBlackhole | MediaRecorder
            if self.record_to:
                recorder = MediaRecorder(self.record_to)
            else:
                recorder = MediaBlackhole()
            recorder.addTrack(call.audioTransceiver.receiver.track)
            await recorder.start()

            # Accept the incoming call.
            await call.accept(request)

            # Ensure the call is hung up 15s later.
            asyncio.create_task(ensure_hangup(call, recorder))
        else:
            # Reject any other requests.
            await super().handle_request(request)


async def main() -> None:
    parser = argparse.ArgumentParser("sip server")
    parser.add_argument("--local-host", type=str, default="127.0.0.1")
    parser.add_argument("--local-port", type=int, default=5060)
    parser.add_argument(
        "--play-from", type=str, help="Read the media from a file and sent it."
    )
    parser.add_argument("--record-to", type=str, help="Write received media to a file.")
    options = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    server = SipServer(play_from=options.play_from, record_to=options.record_to)
    await server.listen(
        sipua.TransportAddress("udp", options.local_host, options.local_port)
    )
    try:
        await asyncio.Future()
    finally:
        await server.close()


if __name__ == "__main__":
    asyncio.run(main())
