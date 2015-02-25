# Copyright (C) 2014  Sangoma Technologies Corp.
# All Rights Reserved.
#
# Author(s)
# Leonardo Lang <lang@sangoma.com>
#
# This modules provides a mostly IPTC-compatible interface which
# uses ip{,6}tables-{save,restore} for loading/saving rules.

import os
import sys
import shlex
import logging
import logging.handlers
import subprocess
import socket
import traceback
import errno
import struct
import time
import fcntl
import ConfigParser

from . import IptcMain, IptcCache, IPTCError, pytables_socket

MODULE_NAME = 'pytables-client'
CONFIG_NAME = '/etc/pytables/clients.conf'

class LineRecvBuffer():

    def __init__(self):
        self.buff = ''

    def recv(self, sock):
        pos, cur, lst = 0, 0, []

        IptcMain.logger.debug('receiving data from server')
        res = sock.recv(4096)
        if len(res) == 0:
            raise IPTCError('connection closed')

        self.buff += res
        while pos < len(self.buff):
            cur = self.buff.find('\n', pos)
            if cur == -1:
                break
            lst.append(self.buff[pos:cur])
            pos = cur + 1

        if pos != 0:
            self.buff = self.buff[pos:]

        return lst


class ManagerInstance(object):

    def __init__(self, mode):
        self.loaded = False
        self.failed = False

        self.mode = mode
        self.sock = None

        self.recv_buffer = LineRecvBuffer()
        self.save_buffer = {}
        self.chain_hooks = {}

    def start(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        for attempt in range(0, 5):
            try:
                self.sock.connect(pytables_socket(self.mode))
                self.sock.setblocking(1)
                IptcMain.logger.debug('connection successfull!')
                break
            except socket.error as e:
                Manager.checkServer(self.mode)
                IptcMain.logger.warning(
                    'connection failed: {s}, trying again...'.format(s=str(e)))
                time.sleep(0.5)
        else:
            raise IPTCError('too many failed connection attempts, giving up')

    def send(self, data):
        if self.sock is None:
            self.start()

        IptcMain.logger.debug(
            '({mode}) sending: {data}'.format(mode=self.mode, data=data))
        self.sock.send(data + '\n')

    def recv(self):
        if self.sock is None:
            self.start()

        return self.recv_buffer.recv(self.sock)

    def restart(self):
        self.resync()

    def resync(self):
        IptcMain.logger.debug('requested manager resync')

        if not self.loaded:
            self.load()
            self.loaded = True
        else:
            self.load(False)

    def close(self):
        if not self.failed:
            return

        self.failed = False

    def load(self, force=True):
        IptcMain.logger.debug('loading data from server process')

        self.send('LOAD' if force else 'SYNC')

        data, okey = [], False

        for line in self.recv():
            if line == 'OK':
                okey = True
                break

            if line.startswith('FAILURE/'):
                raise IPTCError(line[8:])

            data.append(line)

        if okey and len(data) == 0:
            return

        IptcCache.load(self.mode, data, autoload=False)

    def update(self, tblname, data, hook=None):
        buffdata = self.save_buffer.get(tblname)

        if buffdata is None:
            self.save_buffer[tblname] = list(data)
        else:
            buffdata.extend(data)

        if hook is not None:
            hookdata = self.chain_hooks.get(tblname)

            if hookdata is None:
                self.chain_hooks[tblname] = [hook]
            else:
                hookdata.append(hook)

        IptcMain.logger.debug(
            'buffering {n} lines for table {mode}.{name}...'.format(n=len(data), mode=self.mode, name=tblname))

    def save(self):
        loop = True

        for (tblname, data) in self.save_buffer.items():
            try:
                self.send('SAVE')
                self.send('TABLE/' + tblname)
                for ln in data:
                    self.send(ln)
                self.send('COMMIT')

                resp = []
                while len(resp) == 0:
                    resp = self.recv()

                if resp[0].startswith('FAILURE/'):
                    raise IPTCError(resp[0][8:])

                hooks = self.chain_hooks.get(tblname)
                if hooks is not None:
                    for hook in hooks:
                        hook.run()

            except IOError, e:
                self.loaded = False
                self.failed = True
                self.save_buffer = {}
                raise IPTCError(str(e))

            except IPTCError, e:
                self.loaded = False
                self.failed = True
                self.save_buffer = {}
                raise

        self.save_buffer = {}


class Manager(object):
    MANAGERS = {
        'ipv4': ManagerInstance(mode='ipv4'),
        'ipv6': ManagerInstance(mode='ipv6')
    }

    initialized = False

    autostart = None
    autoservers = dict()

    @classmethod
    def checkServer(cls, mode):
        IptcMain.logger.debug('checking server autostart ({!s}abled)'.format('en' \
            if cls.autostart else 'dis'))
        if not cls.autostart or mode in cls.autoservers:
            return False

        from server import Server
        cls.autoservers[mode] = Server.create(mode)
        return True

    @classmethod
    def manager(cls, mode):
        cls.checkServer(mode)
        return Manager.MANAGERS.get(mode)

    @classmethod
    def getEnvAutoStart(cls):
        return os.environ.get('PYTABLES_SERVER_AUTOSTART', '0') != '0'

    @classmethod
    def initialize(cls):
        if cls.initialized:
            return

        cls.initialized = True

        optdebug, optdisk, optconsole = None, True, False

        config = ConfigParser.SafeConfigParser()

        try:
            if len(config.read(CONFIG_NAME)) == 0:
                raise Exception()

            sections = config.sections()
            progname = os.path.basename(os.path.abspath(sys.argv[0]))

            def safeget(sec, name, defvalue, conv):
                try:
                    return conv(config.get(sec, name))
                except:
                    return defvalue

            secname = progname if progname in sections else 'default'

            def tobool(data):
                data = data.lower()
                try:
                    return bool(int(data))
                except:
                    return data == 'true' or data == 'yes' or data == 'y'

            optdebug = safeget(secname, 'debug', optdebug, tobool)
            optdisk = safeget(secname, 'disk',  optdisk, tobool)
            optconsole = safeget(secname, 'console', optconsole, tobool)

            cls.autostart = safeget(secname, 'auto-start', cls.autostart, tobool)
        except:
            pass

        optdebug = IptcMain.getEnvironmentDebug() if optdebug is None else optdebug

        if cls.autostart is None:
            cls.autostart = cls.getEnvAutoStart()

        IptcMain.initialize('{}-{}'.format(MODULE_NAME, progname), debug=optdebug,
            disk=optdisk, console=optconsole)

if __name__ == "__main__":
    from . import Table, Table6, Chain, Rule, Target, Match

    print 'Loading...'

    tbl = Table6('nat', True)
    tbl.restart()

    tbl2 = Table('filter', True)
    tbl2.restart()

    print 'Creating...'

    for num in range(0, 100):
        rule = Rule()
        rule.protocol = 'udp'
        match = Match(rule, 'udp')
        match.dport = '1234'
        rule.add_match(match)
        rule.target = Target(rule, 'ACCEPT')
        chain = Chain(tbl, 'POSTROUTING')
        chain.insert_rule(rule)

    print str(tbl.dump())
    print str(tbl2.dump())

#    # pytables.py dump
#    if len(sys.argv) > 1 and sys.argv[1] == 'dump':
#        dump_current_cache()

    print 'Done!'

    sys.exit(0)
