#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import importlib.metadata

from .transport import Transport, TransportAddress

__all__ = [
    "Transport",
    "TransportAddress",
]
__version__ = importlib.metadata.version("sipua")
