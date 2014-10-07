#!/usr/bin/env python
# vim: tabstop=4 softtabstop=4 shiftwidth=4 textwidth=80 smarttab expandtab
# coding: utf-8

"""
* Copyright (C) 2014  Sangoma Technologies Corp.
* All Rights Reserved.
*
* Author(s)
* Leonardo Lang <lang@sangoma.com>
"""

try:
    from setuptools import setup

    extras = dict(zip_safe=False)
except ImportError:
    from distutils.core import setup
    extras = {}

setup(name='pytables',
    version='0.1',
    description='Pure-python iptc-compatible iptables frontend',
    author='Sangoma Technologies',
    author_email='langy@sangoma.com',
    packages=['pytables'],
    package_dir={'pytables': 'src'},
)

