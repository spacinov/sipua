#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import secrets
import string


def random_string(length: int) -> str:
    allchar = string.ascii_letters + string.digits
    return "".join(secrets.choice(allchar) for x in range(length))


def response_establishes_dialog(method: str, code: int) -> bool:
    return method == "INVITE" and code > 100 and code < 300
