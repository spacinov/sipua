#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import asyncio
import enum

import pylibsrtp
import sipmessage
from aiortc import (
    AudioStreamTrack,
    RTCCertificate,
    RTCDtlsParameters,
    RTCDtlsTransport,
    RTCIceCandidate,
    RTCIceGatherer,
    RTCIceParameters,
    RTCIceServer,
    RTCIceTransport,
    RTCRtpReceiver,
    RTCRtpSender,
    RTCRtpTransceiver,
    clock,
    sdp,
)
from aiortc.codecs import CODECS
from aiortc.rtcdtlstransport import State
from aiortc.rtcpeerconnection import filter_preferred_codecs, find_common_codecs
from aiortc.rtcrtpparameters import RTCRtpReceiveParameters, RTCRtpSendParameters
from aiortc.rtcrtpreceiver import RemoteStreamTrack

from .dialog import Dialog, DialogLayer
from .utils import create_contact

COMPONENT_RTP = 1


class FakeSsl:
    def DTLSv1_get_timeout(self) -> None:
        return None


class FakeDtlsSession(pylibsrtp.Session):
    def protect(self, data: bytes) -> bytes:
        return data

    def protect_rtcp(self, data: bytes) -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data

    def unprotect_rtcp(self, data: bytes) -> bytes:
        return data


class FakeDtlsTransport(RTCDtlsTransport):
    fake = True

    def getLocalParameters(self) -> RTCDtlsParameters:
        return RTCDtlsParameters(fingerprints=[])

    async def start(self, parameters: RTCDtlsParameters) -> None:
        self._ssl = FakeSsl()  # type: ignore
        self._rx_srtp = FakeDtlsSession()
        self._tx_srtp = FakeDtlsSession()

        self._set_state(State.CONNECTED)
        asyncio.ensure_future(self.__run())

    async def stop(self) -> None:
        pass

    async def __run(self) -> None:
        try:
            while True:
                await self._recv_next()
        except ConnectionError:
            for receiver in self._rtp_router.receivers:
                receiver._handle_disconnect()  # pragma: no cover
        finally:
            self._set_state(State.CLOSED)


def create_rtp_transceiver(transport: RTCDtlsTransport) -> RTCRtpTransceiver:
    kind = "audio"

    transceiver = RTCRtpTransceiver(
        direction="sendrecv",
        kind=kind,
        sender=RTCRtpSender(AudioStreamTrack(), transport),
        receiver=RTCRtpReceiver(kind, transport),
    )
    transceiver.receiver._set_rtcp_ssrc(transceiver.sender._ssrc)
    transceiver.receiver._track = RemoteStreamTrack(kind=kind)
    return transceiver


class CallState(enum.Enum):
    Created = 0
    Established = 1
    Terminated = 2


class Call(Dialog):
    """
    A SIP call with support for RTP.
    """

    def __init__(
        self,
        *,
        call_id: str,
        dialog_layer: DialogLayer,
        dtls: bool = False,
        local_address: sipmessage.Address,
        remote_address: sipmessage.Address,
        remote_uri: sipmessage.URI,
        route_set: list[sipmessage.Address] = [],
        stun_server: str | None = None,
    ) -> None:
        super().__init__(
            call_id=call_id,
            dialog_layer=dialog_layer,
            local_address=local_address,
            remote_address=remote_address,
            remote_uri=remote_uri,
            route_set=route_set,
        )

        self.__remoteDtls: RTCDtlsParameters | None = None
        self.__remoteIce: RTCIceParameters | None = None
        self.__skip_ice = False
        self.__state = CallState.Created

        # Create ICE transport.
        iceServers = []
        if stun_server:
            iceServers.append(RTCIceServer(stun_server))
        iceGatherer = RTCIceGatherer(iceServers=iceServers)
        self.__iceTransport = RTCIceTransport(iceGatherer)

        # Create DTLS transport.
        cls = RTCDtlsTransport if dtls else FakeDtlsTransport
        self.__dtlsTransport = cls(
            self.__iceTransport, [RTCCertificate.generateCertificate()]
        )

        # Create RTP sender / receiver.
        self.__rtpTransceiver = create_rtp_transceiver(self.__dtlsTransport)

    @property
    def audioTransceiver(self) -> RTCRtpTransceiver:
        """
        The RTP transceiver used for audio.
        """
        return self.__rtpTransceiver

    async def accept(self, request: sipmessage.Request) -> None:
        """
        Accept an incoming call by sending a `200` response.
        """
        self.__iceTransport._connection.ice_controlling = False

        await self._handle_sdp(request.body.decode())

        response = self.create_response(request, 200)
        response.content_type = "application/sdp"
        response.body = (await self._create_sdp()).encode()

        # Send response and start media flow.
        await self.send_response(response)
        await self._media_connect()

    async def hangup(self) -> None:
        """
        Hangup the call by sending a `BYE` request.
        """
        if self.__state != CallState.Established:
            return

        request = self.create_request("BYE")
        await self.send_request(request)
        await self._media_close()

    async def invite(self, extra_headers: list[tuple[str, str]] = []) -> None:
        """
        Make an outgoing call by sending an `INVITE` request.

        If you wish to send additional headers in the `INVITE`, specify
        them in ``extra_headers``.
        """
        self.__iceTransport._connection.ice_controlling = True
        self.__rtpTransceiver._codecs = filter_preferred_codecs(
            CODECS[self.__rtpTransceiver.kind][:],
            self.__rtpTransceiver._preferred_codecs,
        )

        request = self.create_request("INVITE")
        request.content_type = "application/sdp"
        request.body = (await self._create_sdp()).encode()
        for key, value in extra_headers:
            request.headers.add(key, value)

        response = await self.send_request(request)
        if response.code >= 200 and response.code < 300:
            # Parse SDP and start media flow.
            await self._handle_sdp(response.body.decode())
            await self._media_connect()
        else:
            # Shutdown media and raise an exception.
            await self._media_close()
            raise Exception(f"Call failed: {response.code} {response.phrase}")

    async def handle_request(self, request: sipmessage.Request) -> None:
        if request.method == "BYE":
            response = self.create_response(request, 200)
            response.contact = [create_contact()]
            await self._dialog_layer._transaction_layer.send_response(response)
            await self._media_close()

    async def _create_sdp(self) -> str:
        await self.__iceTransport.iceGatherer.gather()

        ntp_seconds = clock.current_ntp_time() >> 32
        session = sdp.SessionDescription()
        session.origin = "- %d %d IN IP4 0.0.0.0" % (ntp_seconds, ntp_seconds)

        media = sdp.MediaDescription(
            kind=self.__rtpTransceiver.kind,
            port=9,
            profile=(
                "RTP/AVP"
                if hasattr(self.__dtlsTransport, "fake")
                else "UDP/TLS/RTP/SAVPF"
            ),
            fmt=[c.payloadType for c in self.__rtpTransceiver._codecs],
        )
        media.host = "0.0.0.0"
        media.direction = "sendrecv"

        # ice
        iceGatherer = self.__iceTransport.iceGatherer
        media.ice_candidates = iceGatherer.getLocalCandidates()
        media.ice_candidates_complete = iceGatherer.state == "completed"
        media.ice = iceGatherer.getLocalParameters()
        if media.ice_candidates:
            media.host = media.ice_candidates[0].ip
            media.port = media.ice_candidates[0].port

        # dtls
        media.dtls = self.__dtlsTransport.getLocalParameters()

        # rtp
        media.rtcp_host = "0.0.0.0"
        media.rtcp_port = 9
        media.rtcp_mux = True
        media.rtp.codecs = self.__rtpTransceiver._codecs

        session.media.append(media)

        return str(session)

    async def _handle_sdp(self, value: str) -> None:
        session = sdp.SessionDescription.parse(value)
        media = session.media[0]
        assert media.kind == "audio", "Only audio is supported"

        # codecs
        common = filter_preferred_codecs(
            find_common_codecs(CODECS[self.__rtpTransceiver.kind], media.rtp.codecs),
            self.__rtpTransceiver._preferred_codecs,
        )
        assert len(common), "No common codecs found"
        self.__rtpTransceiver._codecs = common

        # ice
        self.__remoteIce = media.ice
        for candidate in media.ice_candidates:
            await self.__iceTransport.addRemoteCandidate(candidate)
        if not media.ice_candidates:
            # remote host does not support ICE
            default_host = media.host or session.host
            default_port = media.port
            assert default_host is not None
            await self.__iceTransport.addRemoteCandidate(
                RTCIceCandidate(
                    foundation="default",
                    component=1,
                    ip=default_host,
                    protocol="udp",
                    priority=1,
                    port=default_port,
                    type="host",
                )
            )
            await self.__iceTransport.addRemoteCandidate(
                RTCIceCandidate(
                    foundation="default",
                    component=2,
                    ip=default_host,
                    protocol="udp",
                    priority=1,
                    port=default_port + 1,
                    type="host",
                )
            )
            self.__skip_ice = True

        # dtls
        self.__remoteDtls = media.dtls

    async def _media_connect(self) -> None:
        if self.__skip_ice:
            connection = self.__iceTransport._connection
            default_candidate = connection.get_default_candidate(COMPONENT_RTP)
            assert default_candidate is not None, "No default RTP candidate"
            connection.set_selected_pair(
                COMPONENT_RTP, default_candidate.foundation, "default"
            )
        else:
            await self.__iceTransport.start(self.__remoteIce)  # type: ignore
        await self.__dtlsTransport.start(self.__remoteDtls)  # type: ignore
        await self.__rtpTransceiver.sender.send(
            RTCRtpSendParameters(codecs=self.__rtpTransceiver._codecs)
        )
        await self.__rtpTransceiver.receiver.receive(
            RTCRtpReceiveParameters(codecs=self.__rtpTransceiver._codecs)
        )
        self.__state = CallState.Established

    async def _media_close(self) -> None:
        await self.__rtpTransceiver.stop()
        await self.__dtlsTransport.stop()
        await self.__iceTransport.stop()
        self._dialog_layer._dialog_terminated(self)
        self.__state = CallState.Terminated
