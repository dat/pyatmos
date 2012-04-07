#!/usr/bin/env python

import httplib
import logging
import random
import socket

from itertools import count

from .errors import *
from .utils import (
    xml2dict, get_ipaddrlist
)


class Connection(object):
    """Manages the TCP/IP connection to the Atmos server cloud."""

    DEFAULT_TIMEOUT = 30            #seconds
    UNLIMITED       = float('inf')  #infinity
    DEFAULT_PORT       = httplib.HTTP_PORT #80

    def __init__(self, host, port=DEFAULT_PORT, secured=False, retries=UNLIMITED, timeout=DEFAULT_TIMEOUT, encoding='utf-8'):
        self.host = host
        self.port = port
        self.retries = retries
        self.timeout = timeout
        self.encoding = encoding
        self.secured = secured

        # all possible IP addresses associated with that host/port
        self.__ip_pool = get_ipaddrlist(host, port=port)
        # pick a random IP to connect to
        self.__active_ip = self.__conn = None
        self.rotate_ip()

    def __del__(self):
        """Make sure we do proper cleanup."""
        try:
           self.disconnect()
        except:
           pass

    def rotate_ip(self):
        """Rotate to another IP address in the pool."""
        self.disconnect()
        self.__active_ip = random.choice(self.__ip_pool)
        self.connect()

    def connect(self):
        """Establish connection with the server."""
        if self.__conn:
            return

        #TODO: add timeout keyword parameter
        socket.setdefaulttimeout(self.timeout)
        try:
            if self.secured:
                conn = httplib.HTTPConnection(self.__active_ip, port=self.port)
            else:
                conn = httplib.HTTPConnection(self,__active_ip, port=self.port)
        except HTTPException:
            raise ConnectionError("Cannot establish connection with server on (%s, %s)." %
                (self.__active_ip, self.port))
        
        self.__conn = conn

    def disconnect(self):
        """Tear down the connection."""
        if self.__conn is None:
            return

        try:
            self.__conn.close()
        except HTTPException:
            pass

        self.__conn = None

    def reconnect(self):
        """Reestablish connection."""
        self.disconnect()
        self.connect()

    def send_request(self, method, uri, body=None, headers=dict()):
        """Send the HTTP request to the Atmos server and correctly retry
        and timeout. If the request fails to go through, it will rotate
        to another IP address and try again until maximum retries
        is reached.

        :param method: HTTP method (POST|GET|HEAD|PUT|DELETE|...)
        :param uri: Universal Resource Identifier
        :param body: (optional) byte string as HTTP body
        :param headers: (optional) dict of HTTP headers
        "returns: :class:`httplib.HTTPResponse` object
        """
        assert body is None or isinstance(body, str)
        assert isinstance(headers, dict)
        
        resp = None
        for i in count(1):
            if i > self.retries:
                break
            
            logging.info("[Retry #%d] REQUEST HTTP Headers:" % i)
            logging.info("%s http//%s%s" % (method, self.__active_ip, uri))
            logging.debug("REQUEST Headers: ")
            for k, v in headers.items():
                logging.debug("%s:%s" % (k, v))

            try:
                if body and isinstance(body, str):
                    self.__conn.request(method, uri, headers=headers)
                else:
                    # we have to encode this because HTTPConnection doesn't
                    # correctly allow body="" to send an empty string
                    headers['content-length'] = '0'
                    self.__conn.request(method, uri, headers=headers)
                resp = self.__conn.getresponse()
            except NoneType:
                raise ConnectionError("Connection is not established yet.")
            except (socket.timeout, socket.error, httplib.CannotSendRequest, httplib.BadStatusLine):
                self.rotate_ip()
                continue
            except:
                raise
            else:
                #succeeeded
                logging.info("[Succeeded] RESPONSE HTTP Headers: ")
                logging.info("%s %s" (resp.status, resp.reason))
                logging.debug("RESPONSE Headers: ")
                for k, v in resp.getheaders():
                    logging.debug("%s:%s" % (k, v))

                if resp is None:
                    raise NoHTTPResponse()
                if resp.status >= 400:
                    status, reason, body = resp.status, resp.reason, resp.read()
                    error = xml2dict(body)
                    logging.info("HTTP response status code %d from host.", status)
                    logging.debug("Error Code: %s", error['Code'])
                    logging.debug("Error Message: %s", error['Message'])
                    raise RequestError(status, reason, error['Code'], erro['Message'])
                else:
                    break

        return resp

