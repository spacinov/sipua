#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import secrets
import string

import sipmessage

ANY_HOST = "any"
ANY_PORT = 0
ANY_TRANSPORT = "ANY"

# https://datatracker.ietf.org/doc/html/rfc3261#section-21
SIP_STATUS_CODES = {
    100: "Trying",
    180: "Ringing",
    181: "Call Is Being Forwarded",
    182: "Queued",
    183: "Session Progress",
    200: "OK",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    305: "Use Proxy",
    380: "Alternative Service",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    410: "Gone",
    413: "Request Entity Too Large",
    414: "Request-URI Too Long",
    415: "Unsupported Media Type",
    416: "Unsupported URI Scheme",
    420: "Bad Extension",
    421: "Extension Required",
    423: "Interval Too Brief",
    480: "Temporarily Unavailable",
    481: "Call/Transaction Does Not Exist",
    482: "Loop Detected",
    483: "Too Many Hops",
    484: "Address Incomplete",
    485: "Ambiguous",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    491: "Request Pending",
    493: "Undecipherable",
    500: "Server Internal Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Server Time-out",
    505: "Version Not Supported",
    513: "Message Too Large",
    600: "Busy Everywhere",
    603: "Decline",
    604: "Does Not Exist Anywhere",
    606: "Not Acceptable",
}


def create_ack(
    *,
    request: sipmessage.Request,
    response: sipmessage.Response,
) -> sipmessage.Request:
    """
    Create an ACK for the given request and response.

    See :rfc:`3261#section-17.1.1.3`.
    """

    # The `Contact` header indicates the address to use for subsequent
    # requests, including the ACK.
    #
    # https://datatracker.ietf.org/doc/html/rfc3261#section-12.1.1
    if response.contact:
        request_uri = response.contact[0].uri
    else:
        request_uri = request.uri

    ack = sipmessage.Request("ACK", request_uri)
    ack.via = [request.via[0]]
    ack.to_address = response.to_address
    ack.from_address = request.from_address
    ack.call_id = request.call_id
    ack.cseq = sipmessage.CSeq(sequence=request.cseq.sequence, method="ACK")

    ack.authorization = request.authorization
    ack.proxy_authorization = request.proxy_authorization
    ack.route = list(reversed(response.record_route))

    return ack


def create_contact(
    *,
    parameters: sipmessage.Parameters = sipmessage.Parameters(),
) -> sipmessage.Address:
    """
    Create a `Contact` header for a message.

    The host and transport will be filled in when the message is sent.
    """
    return sipmessage.Address(
        uri=sipmessage.URI(
            scheme="sip",
            host=ANY_HOST,
            parameters=parameters,
        ),
    )


def create_response(
    *,
    request: sipmessage.Request,
    code: int,
    phrase: str | None = None,
) -> sipmessage.Response:
    """
    Create a response for the given request.

    See :rfc:`3261#section-8.2.6`.
    """
    if phrase is None:
        phrase = SIP_STATUS_CODES[code]
    response = sipmessage.Response(code, phrase)
    response.via = request.via
    response.to_address = request.to_address
    response.from_address = request.from_address
    response.call_id = request.call_id
    response.cseq = request.cseq

    # Copy the Record-Route headers from the request if the response
    # establishes a dialog.
    #
    # https://datatracker.ietf.org/doc/html/rfc3261#section-12.1.1
    if response_establishes_dialog(request.method, code):
        response.record_route = request.record_route

    return response


def create_via() -> sipmessage.Via:
    """
    Create a `Via` header for a message.

    The host and transport will be filled in when the message is sent.
    """
    return sipmessage.Via(
        transport=ANY_TRANSPORT,
        host=ANY_HOST,
        parameters=sipmessage.Parameters(branch="z9hG4bK" + random_string(7)),
    )


def random_string(length: int) -> str:
    allchar = string.ascii_letters + string.digits
    return "".join(secrets.choice(allchar) for x in range(length))


def response_establishes_dialog(method: str, code: int) -> bool:
    return method == "INVITE" and code > 100 and code < 300
