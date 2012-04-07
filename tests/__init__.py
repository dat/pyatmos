#!/usr/bin/env python

import unittest

from test_utils import UtilsTestCase


def all_tests():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(UtilsTestCase))

    return suite

