#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import importlib.metadata

from .transport import TransportAddress, TransportLayer

__all__ = [
    "TransportAddress",
    "TransportLayer",
]
__version__ = importlib.metadata.version("sipua")
