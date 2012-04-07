#!/usr/bin/env python

import base64
import unittest

from atmos import utils


class UtilsTestCase(unittest.TestCase):
    def setUp(self):
        self.IPS = {
            'www.google.com' : (
                '173.194.73.105',
                '173.194.73.106',
                '173.194.73.147',
                '173.194.73.99',
                '173.194.73.103',
                '173.194.73.104',
            ),
            'localhost' : (
                '127.0.0.1',
            ),
            '4.2.2.1' : (
                '4.2.2.1',
            ),
        }
        self.attr_str = 'val1=1,val2=2,val3=3'
        self.attr_dict = {
            'val1' : '1', 'val2' : '2', 'val3' : '3',
        }

    def tearDown(self):
        pass

    def test_md5sum(self):
        self.assertEqual(utils.md5sum(""), 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(utils.md5sum("test"), '098f6bcd4621d373cade4e832627b4f6')
        self.assertNotEqual(utils.md5sum("test"), utils.md5sum("Test"))

    def test_sha1sum(self):
        self.assertEqual(utils.sha1sum(""), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
        self.assertEqual(utils.sha1sum("test"), 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3')
        self.assertNotEqual(utils.sha1sum("test"), utils.sha1sum("Test"))

    def test_hmacsha1(self):
        key1 = base64.b64encode('key1')
        key2 = base64.b64encode('key2')
        self.assertEqual(utils.hmacsha1(key1, 'msg'),
            '\x7f\xd3\x8d\xe0\x8aw=\xe1Z\xdfg\xaf\x1d\xd2\x88b\xd1\xb5s\x12'
        )
        self.assertEqual(utils.hmacsha1(key2, 'msg'),
            't:\xb3p>\xeb\xfd\xf3\xc1l\x9d\xdeI7\xb4\x83\xe9\xcc\xc8\x9b'
        )
        self.assertNotEqual(utils.hmacsha1(key1, 'test'), utils.hmacsha1(key2, 'test'))
        self.assertNotEqual(utils.hmacsha1(key1, 'test1'), utils.hmacsha1(key1, 'test2'))
        self.assertNotEqual(utils.hmacsha1(key2, 'test1'), utils.hmacsha1(key2, 'test2'))

    def test_get_ipaddrlist(self):
        for host, ips in self.IPS.items():
            tested_ips = utils.get_ipaddrlist(host)
            for ip in ips:
                self.assertIn(ip, tested_ips)

    def test_xml2dict(self):
        xml_str = "<top><keys><key1>1</key1><key2>2</key2><key2>3</key2></keys></top>"
        xml_dict = {'top': {'keys': {'key1': '1', 'key2': ['2', '3']}}}
        self.assertDictEqual(utils.xml2dict(xml_str, top_tag=True), xml_dict)
        self.assertDictEqual(utils.xml2dict(xml_str, top_tag=False), xml_dict['top'])

    def test_attr2dict(self):
        self.assertDictEqual(utils.attr2dict(""), dict())
        self.assertDictEqual(utils.attr2dict("key=1"), {'key':'1'})
        self.assertDictEqual(utils.attr2dict(self.attr_str), self.attr_dict)
        self.assertDictEqual(utils.attr2dict(utils.dict2attr(self.attr_dict)), self.attr_dict)
        self.assertEqual(utils.dict2attr(utils.attr2dict(self.attr_str)), self.attr_str)

    def test_dict2attr(self):
        self.assertEqual(utils.dict2attr(dict()), "")
        self.assertEqual(utils.dict2attr({'key':'1'}), "key=1")
        self.assertEqual(utils.dict2attr(self.attr_dict), self.attr_str)
        self.assertDictEqual(utils.attr2dict(utils.dict2attr(self.attr_dict)), self.attr_dict)
        self.assertEqual(utils.dict2attr(utils.attr2dict(self.attr_str)), self.attr_str)


