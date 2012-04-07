#!/usr/bin/env python

from .client import AtmosClient
from .connection import Connection
from .errors import *


__version__ = '0.1'
VERSION = tuple(map(int, __version__.split('.')))

__all__ = [
    'AtmosClient', 'Connection', 'AtmosError'
]

