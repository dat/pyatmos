#!/usr/bin/env python

import base64
import hmac
import re
import socket
import xml.dom
import xml.dom.minidom

try:
    #Python 2.5+
    from hashlib import md5
except ImportError:
    import md5

try:
    #Python 2.5+
    from hashlib import sha1
except ImportError:
    import sha as sha1
    

def md5sum(val):
    """Returns the MD5 checksum of string val."""
    if hasattr(md5, '__call__'):
        hash = md5()
    else:
        hash = md5.new()
    hash.update(val)
    return hash.hexdigest()

def sha1sum(val):
    """Returns the SHA1 checksum of string val."""
    if hasattr(sha1, '__call__'):
        hash = sha1()
    else:
        hash = sha1.new()
    hash.update(val)
    return hash.hexdigest()

def hmacsha1(key, msg):
    """Returns the HMACSHA1 digest of the messsage encoded using key.

    :param key: key string used to encode
    :param msg: message to encode
    """
    return hmac.new(base64.b64decode(key), msg, sha1).digest()

def get_ipaddrlist(host, port=80):
    """Returns a list of all possible IPv4/v6 addresses for the same
    interface on host, specifically to port.

    :param host: hostname
    :param port: (optional) port to search for
    """
    ipaddrlist = [ sockaddr[0] for (family, socktype, proto, canonname, sockaddr)
        in socket.getaddrinfo(host, port)
        if family in (socket.AF_INET, socket.AF_INET6) and socktype == socket.SOCK_STREAM ]

    return ipaddrlist

def xml2dict(val, top_tag=False):
    """Convert an XML string into a recursive dict.
    Credit: https://github.com/mutaku/xml2json/blob/master/xml2json
    Example:
        xml2dict("<main><val1>1</val1><val2>2</val2><val2>3</val2></main>", top_tag=False) = 
            {
                'val1' : '1',
                'val2' : ['2', '3']
            }
        xml2dict("<main><val1>1</val1><val2>2</val2><val2>3</val2></main>", top_tag=True) =
            {
                'main' : {
                    'val1' : '1',
                    'val2' : ['2', '3']
                }
            }
    
    :param val: XML string
    :param top_tag: (optional) should keep the top most tag or not
    :returns: a dict representing the recursive XML structure
    """
    def element2dict(element):
        if not element.hasChildNodes():
            return "TEXT", str(element.data)

        #normalize so that all Text nodes are merged together
        element.normalize()
        d = {}
        for subelement in element.childNodes:
            #skip non-terminal nodes that aren't an Element
            if subelement.hasChildNodes() and not isinstance(subelement, xml.dom.minidom.Element):
                continue
            #skip terminal nodes that aren't Text
            if not subelement.hasChildNodes() and not isinstance(subelement, xml.dom.minidom.Text):
                continue

            tag, value = element2dict(subelement)
                
            if tag == "TEXT":
                return str(element.tagName), value
            try:
                d[tag].append(value)
            except AttributeError:
                #turn existing entry into a list
                d[tag] = [d[tag], value]
            except KeyError:
                #add a new non-list entry
                d[tag] = value
        return str(element.tagName), d

    val = re.sub(">\s*<", "><", val.strip())
    dom = xml.dom.minidom.parseString(val)
    root_element = dom.childNodes[0]
    tag, info = element2dict(root_element)
    
    if top_tag:
        return { tag : info }
    else:
        return info

def attr2dict(val):
    """Decode an attribute string into a dict.
    Example:
       attr2dict("val=1,val2=2,val3=3") = {'val1':'1', 'val2':'2', 'val3':'3'}

    :param val: attribute string
    :returns: a dict mapping every key to vale in the attr string
    """
    if val:
        return dict(pair.strip().split('=') for pair in val.split(','))
    return dict()

def dict2attr(val):
    """Encode an attribute dict into a string.
    Example:
        dict2attr({'val1':'1', 'val2':'2', 'val3':'3'}) = "val1=1,val2=2,val3=3"

    :param val: a dict
    :returns: an encoded attribute string
    """
    return ",".join(("%s=%s" % (k,v) for k,v in sorted(val.iteritems())))


