#!/usr/bin/env python

class AtmosError(Exception):
    """Base class for all Atmos errors."""

class ChecksumMismatch(AtmosError):
    """File or object checksums mismatch."""

class RequestError(AtmosError):
    """Error encountered when performing HTTP request on an object."""
    def __init__(self, http_status, http_reason, atmos_code=None, atmos_msg=None):
        self.http_status = http_status
        self.http_reason = http_reason
        self.atmos_code = atmos_code
        self.atmos_msg = atmos_msg

    def __str__(self):
        return "<%s (status=%s, reason=%s, atmos_code=%s, atmos_msg=%s)>\n" % (
            self.http_status, self.http_reason, self.atmos_code, self.atmos_msg
        )

    __repr__ = __str__

class NoHTTPResponse(AtmosError):
    """Cannot get any HTTP response from the system."""

class InvalidHeader(AtmosError):
    """Invalid HTTP header was passed."""

class ConnectionError(AtmosError):
    """Cannot establish connection with the Atmos server."""

