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


class SipClient(sipua.Application):
    async def invite(
        self,
        *,
        local_address: sipmessage.Address,
        remote_address: sipmessage.Address,
        play_from: str,
        record_to: str,
    ) -> None:
        call = sipua.Call.create_uac(
            dialog_layer=self.dialog_layer,
            local_address=local_address,
            remote_address=remote_address,
        )

        # Play audio from a file or fall back to silence.
        if play_from:
            player = MediaPlayer(play_from)
            call.audioTransceiver.sender.replaceTrack(player.audio)

        # Consume received audio.
        recorder: MediaBlackhole | MediaRecorder
        if record_to:
            recorder = MediaRecorder(record_to)
        else:
            recorder = MediaBlackhole()
        recorder.addTrack(call.audioTransceiver.receiver.track)
        await recorder.start()

        # Make the call.
        await call.invite()

        # Send media for a few seconds.
        await asyncio.sleep(5)

        # Hangup the call.
        await call.hangup()

        # Stop recording.
        await recorder.stop()


async def main() -> None:
    parser = argparse.ArgumentParser("sip client")
    parser.add_argument("--local-username", type=str, default="+33122334455")
    parser.add_argument("--local-host", type=str, default="127.0.0.1")
    parser.add_argument("--local-port", type=int, default=5061)
    parser.add_argument(
        "--play-from", type=str, help="Read the media from a file and sent it."
    )
    parser.add_argument("--record-to", type=str, help="Write received media to a file.")
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
        # Media playback and recording.
        play_from=options.play_from,
        record_to=options.record_to,
    )
    await app.close()
    await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
