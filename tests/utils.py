#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import asyncio
import functools
from collections.abc import Callable, Coroutine
from typing import ParamSpec, TypeVar

import sipmessage

P = ParamSpec("P")
T = TypeVar("T")


def asynctest(
    coro: Callable[P, Coroutine[None, None, None]],
) -> Callable[P, None]:
    @functools.wraps(coro)
    def wrap(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(coro(*args, **kwargs))

    return wrap


def lf2crlf(x: bytes) -> bytes:
    return x.replace(b"\n", b"\r\n")


def parse_request(data: bytes) -> sipmessage.Request:
    message = sipmessage.Message.parse(lf2crlf(data))
    assert isinstance(message, sipmessage.Request)
    return message


def parse_response(data: bytes) -> sipmessage.Response:
    message = sipmessage.Message.parse(lf2crlf(data))
    assert isinstance(message, sipmessage.Response)
    return message
