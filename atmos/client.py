#!/usr/bin/env python

import base64
import datetime
import httplib
import logging
import random
import socket
import urllib

from itertools import count

from .connection import Connection
from .errors import *
from .utils import (
    sha1sum, hmacsha1, xml2dict, attr2dict, dict2attr
)


class AtmosClient(object):
    """Client API to interface with Atmos."""

    def __init__(self, hostname, uid, shared_secret,
        port=Connection.DEFAULT_PORT, max_retries=Connection.UNLIMITED,
        timeout=Connection.DEFAULT_TIMEOUT):
        """Construct an Atmos REST API object with (uid, shared_secret) to host.

        :param hostname: hostname or IP address
        :param uid: UID provisioned
        :param shared_secret: shared secret
        :param port: (optional) port to connect to
        :param max_retries: (optional) maximum number of HTTP retries
        :param timeout: (optional) socket timeout period
        """
        self.atmos_host = hostname
        self.atmos_uid = uid
        self.atmos_shared_secret = shared_secret
        self.atmos_port = port
        
        self.__conn = Connection(
            host=self.atmos_host,
            retries=max_retries,
            timeout=tieout
        )
        self.connect()

    def __del__(self):
        """Cleanup."""
        self.disconnect()

    def connect(self):
        self.__conn.connect()

    def disconnect(self):
        self.__conn.disconnect()

    def __request(self, method, uri, body=None, headers=dict()):
        """Make an HTTP request to the given URI.

        :param method: GET|POST|DELETE|PUT|HEAD|...
        :param uri: Uniform Resource Identifier, /like/this/for/example
        :param body: (optional) string of text to include in the request body
        :param headers: (optional) a dict of HTTP headers to include
        :returns: :class:`httplib.HTTPResponse` object
        """
        resp = None

        #check that all header names and values are allowed by Atmos
        for k, v in headers.items():
            try:
                k.decode('latin_1')
                v.decode('latin_1')
            except:
                raise InvalidHeader("Invalid header (%s, %s)." % (k, v))

        encoded_headers = self.__gen_http_headers(method, uri, headers=headers)
        logging.info("Header used for the %s request to %s: \n%s\n", method, uri, str(encoded_headers))
        return self.__conn.send_request(method, uri, body=body, headers=encoded_headers)

    def __gen_http_headers(self, method, uri, headers=dict()):
        """Generate an HTTP request header that encapsulates the
        HTTP method, uri, and additional header string.

        :param method: GET|POST|DELETE|PUT|HEAD|...
        :param uri: Universal Resource Identifier
        :param header: (optional) a dict of (key,val) headers you want to include also
        :returns: an encoded header dict
        """
        #EMC requires a specific format for date (RFC 1123)
        #Example: Tue, 07 Apr 2012 22:30:59 GMT
        #Atmos uses timestamps to enforce a request-validity window.
        #This is designed to protect against replay attacks. By
        #default, this is plus or minus 5 mins from the server time
        #in UTC.
        now = datetime.datetime.utcnow()
        timestamp = now.strftime("%a, %d %b %Y %H:%M:%S GMT")

        #this is the default anyway
        content_type = "application/octet-stream"

        #encode additional UID and timestamp in request
        headers['x-emc-uid'] = self.atmos_uid
        headers['x-emc-date'] = timestamp

        #basic components of a HashString
        #Ref: EMC Atmos Programmer's guide, Chapter 6 Security
        components = [
            method, content_type, headers.get('Range', ''),
            timestamp, urllib.unquote(uri).lower(),
        ]
        #canonicalization of EMC headers then merge them in
        for k, v in sorted(headers.items()):
            #skip these headers
            if k.lower() in ('range', 'content-length'):
                continue
            #sanitize and remove multiple spaces
            val = " ".join(str(val).strip().split())
            components.append("%s:%s" % (k.lower(), v))

        #construct the actual HashString now
        hash_string = "\n".join(components)

        #construct the REST authentication signature
        #Ref: EMC Atmos Programmer's Guide, Chapter 6 Security
        # signature := Base64(HMACSHA1(key=shared_secret, msg=HashString))
        signature = base64.b64encode(hmacsha1(self.atmos_shared_secret, hash_string))

        #this is the authenticated header
        encoded_headers = {
            'x-emc-signature' : signature,
            'date' : timestamp,
            'content-type' : content_type
        }
        encoded_headers.update(headers)

        return encoded_headers

    def service(self):
        """Returns detailed info about the Atmos service."""
        resp = self.__request("GET", '/rest/service')
        return xml2dict(resp.read())

    def create(self, filename=None, data=None, verify=False):
        """Create an Atmos object with initial data and return its object ID.

        :param filename: (optional) use namespace interface and post it under this filename
        :param data: (optional) initial data string
        :param verify: (optional) whether we should verify the content of the object created
        :returns: object ID string
        """
        assert filename is None or isinstance(filename, str)
        assert date is None or isinstance(data, str)

        if filename:
            resp = self.__request("POST", '/rest/namespace/%s' % filename, body=data)
        else:
            resp = self.__request("POST", '/rest/objects', body=data)

        location = resp.getheader('location')
        obj_id = location.lstrip('/rest/objects/')

        if data and verify:
            orig_checksum = sha1sum(data)
            obj = self.read(obj_id)
            obj_checksum = sha1sum(obj)
            if orig_checksum != obj_checksum:
                raise ChecksumMismatch("Checksum error between source data and object created.")

        return obj_id

    def delete(self, obj_id):
        """Deletes the specified object.

        :param obj_id: object ID
        :returns: the number of bytes removed from service if successfull
        """
        bytes_deleted = 0

        resp = self.__request("DELETE", '/rest/objects/%s' % obj_id)
        delta_hdr = resp.getheadr('x-emc-delta')
        if delta_hdr and delta_hdr.startswith("-"):
            bytes_deleted = int(delta_hdr[1:])

        return bytes_deleted

    __delitem__ = delete

    def update(self, obj_id, data):
        """Appends content to object.

        :param obj_id: object ID
        :param data: data to append to current object
        :returns; the number of bytes written
        """
        assert isinstance(data, str)
        
        current_meta = self.get_system_metadata(obj_id)
        current_size = int(current_meta['size'])
        append_size = len(data)
        new_size = current_size + append_size

        headers = {
            'Range' : "Bytes=%d-%d" % (current_size, (new_size - 1)),
        }

        self.__request("PUT", '/rest/objects/%s' % obj_id, body=data, headers=headers)
        return append_size

    def read(self, obj_id, range=None):
        """Reads the object data.

        :param obj_id: object ID
        :param range: (optional) an int 2-tuple representing (start_position, end_position) to read
        :returns: a byte string of the object [in range]
        """
        assert range is None or (isinstance(range, (tuple, list)) and len(range) == 2)

        headers = dict()
        if range:
            headers['Range'] = "Byte=%s-%s" % (str(range[0]), str(range[1]))

        resp = self.__request("GET", '/rest/objects/%s' % obj_id, headers=headers)
        return resp.read()

    __getitem__ = read

    def truncate(self, obj_id):
        """Truncate the specified object to zero.

        :param obj_id: object ID
        """
        self.__request("PUT", '/rest/objects/%s' % obj_id, headers={'content-length' : '0'})

    def replace(self, obj_id, data, verify=False):
        """Replace the content of the object.

        :param obj_id: object ID
        :param data: data to replace the object's current content with
        :param verify: (optional) whether we should verify the content of the object created
        :returns: the number of bytes written
        """
        assert data is None or isinstance(data, str)

        self.__request("PUT", "/rest/objects/%s" % obj_id, body=data)

        if verify:
            obj = self.read(obj_id)
            orig_checksum = sha1sum(data)
            obj_checksum = sha1sum(obj)
            if orig_checksum != obj_checksum:
                raise ChecksumMismatch("Checksum error between source data and object created.")

        return len(data)

    __setitem__ = replace

    def splice(self, obj_id, data, range):
        """Replace the content within the specified object within range.

        :param obj_id: object ID
        :param range: integer tuple (start, end) of where to splice
        :param data: data to insert in the range
        :returns: the number of bytes written
        """
        assert isinstance(range, (tuple, list)) and len(range) == 2

        self.__request("PUT", "/rest/objects/%s" % obj_id,
            body=data,
            headers={ 'Range' : "Bytes=%d-%d" % (int(range[0]), int(range[1])) }
        )

        return len(data)

    def info(self, obj_id):
        """Get detailed information on the object.

        :param obj_id: object ID
        :returns: a dict representing an object's characteristic to its value
        """
        resp = self.__request("GET", "/rest/objects/%s?info" % obj_id)
        obj_info = xml2dict(resp.read())
        #normalize it a bit
        obj_info['replicas'] = obj_info['replicas']['replica']

        return obj_info

    def contains(self, obj_id):
        """Returns true if and only if Atmos knows about this object.

        :param obj_id: object ID
        """
        try:
            self.istat(obj_id)
        except:
            return False
        else:
            return True

    __contains__ = contains

    def get_system_metadata(self, obj_id, tags=list()):
        """Returns a dict of system metadata for object.

        :param obj_id: object ID
        :param tags: (optional) list of specific tags to retrieve
        """
        headers = dict()
        headers['x-emc-tags'] = ",".join(tags)

        resp = self.__request("HEAD", "/rest/objects/%s?metadata/system" % obj_id, headers=headers)
        meta_header = resp.getheader('x-emc-meta')
        meta = attr2dict(meta_header)

        return meta

    istat = get_system_metadata

    def get_user_metadata(self, obj_id, tags=list()):
        """Get user metadata for object.

        :param obj_id: object ID
        :param tags: (optional) list of specific tags to retrieve
        :returns: a tuple of (metadata, listable_metadata) dicts
        """
        headers = dict()
        headers['x-emc-tags'] = ",".join(tags)

        resp = self.__request("HEAD", "/rest/objects/%s?metadata/user" % obj_id, headers=headers)
        meta_header = resp.getheader('x-emc-meta')
        meta = attr2dict(meta_header)
        lmeta_header = resp.getheader('x-emc-listable-meta')
        lmeta = attr2dict(lmeta_header)

        return meta, lmeta

    def set_user_metadata(self, obj_id, listable_meta=None):
        """Set user metadata for object. Either meta or listable meta
        must be provided.

        :param meta: metadata as a dict
        :param listable_meta: listable metadata as a dict
        """
        assert isinstance(meta, dict) or isinstance(listable_meta, dict)

        headers = dict()
        if meta: headers['x-emc-meta'] = dict2attr(meta)
        if listable_meta: headers['x-emc-listable-meta'] = dict2attr(listable_meta)

        self.__request("POST", "/rest/objects/%s?metadata/user" % obj_id, headers=headers)

    def del_user_metadata(self, obj_id, tags=list()):
        """Delete specified user metadata tags from object.

        :param obj_id: object ID
        :param tags: (optional) list of tags to delete
        """
        self.__request("DELETE", "/rest/objects/%s?metadata/user" % obj_id,
            headers={ 'x-emc-tags' : ",".join(tags) }
        )

    def get_ACL(self, obj_id):
        """Get ACL on the specified object.

        :param obj_id: object ID
        :returns: a (user_acl, group_acl) tuple of dicts
        """
        resp = self.__request("HEAD", "/rest/objects/%s?acl" % obj_id)

        user_acl = attr2dict(resp.getheader('x-emc-useracl'))
        group_acl = attr2dict(resp.getheader('x-emc-groupacl'))

        return user_acl, group_acl

    def set_ACL(self, obj_id, user_acl=None, group_acl=None):
        """Set ACL on the specified object.

        :param obj_id: object ID
        :param user_acl: user ACL as a dict of (user, permission)
        :param group_acl: group ACL as a dict of (group, permission)
        """
        assert isinstance(user_acl, dict) or isinstance(group_acl, dict)

        headers = dict()
        if user_acl: headers['x-emc-useracl'] = dict2attr(user_acl)
        if group_acl: headers['x-emc-groupacl'] = dict2attr(group_acl)

        self.__request("POST", "/rest/objects/%s?acl" % obj_id, headers=headers)


        
