#
# Copyright (C) Spacinov SAS
# Distributed under the 2-clause BSD license
#

import importlib.metadata

from .transport import TransportLayer

__all__ = [
    "TransportLayer",
]
__version__ = importlib.metadata.version("sipua")
