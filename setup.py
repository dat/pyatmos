#!/usr/bin/env python

import os

from atmos import __version__

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


desc = {
    'name' : 'atmos'
    'version' : __version__,
    'description' : 'Python API for Atmos cloud storage.',
    'url' : 'http://dat.github.com/pyatmos',
    'author' : 'Dat Hoang',
    'keywords' : ['atmos', 'REST', 'cloud storage'],
    'license' : 'GPLv3',
    'packages' : ['atmos'],
    'test_suite' : 'tests.all_tests',
    'classifiers' : (
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ),
}

if __name__=='__main__':
    setup(**desc)

