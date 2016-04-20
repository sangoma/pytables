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

from setuptools.command.install import install as _install

datafiles = [
    ('/usr/bin',        ['bin/pytables-server']),
    ('/etc/init.d',     ['scripts/init/pytables']),
    ('/etc/pytables',   ['conf/clients.conf', 'conf/server.conf']),
]

execfiles = [
    '/usr/bin/pytables-server',
    '/etc/init.d/pytables'
]

class install(_install):
    def run(self):
        _install.run(self)

        rootdir = (lambda x: '' if x is None else x)(getattr(self, 'root', None))

        import os
        import stat

        for filename in execfiles:
            fullname = os.path.normpath(rootdir + '/' + filename)
            st = os.stat(fullname)
            os.chmod(fullname, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

setup(name='pytables',
    cmdclass={'install': install},
    version='0.9',
    description='Pure-python iptc-compatible iptables frontend',
    author='Leonardo Lang',
    author_email='lang@sangoma.com',
    packages=['pytables'],
    package_dir={'pytables': 'src'},
    classifiers=['Development Status :: 4 - Beta',
                 'Programming Language :: Python',
                 'Operating System :: POSIX :: Linux',
                 'Intended Audience :: Developers'],
    data_files=datafiles
)
