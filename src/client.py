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
import multitask as mt
import errno
import struct
import time
import fcntl

from __init__ import *

MODULE_NAME = 'pytables-client'

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
                self.sock.connect(socket_name(self.mode))
                self.sock.setblocking(1)
                IptcMain.logger.debug('connection successfull!')
                break
            except socket.error as e:
                IptcMain.logger.warning(
                    'connection failed: {s}, trying again...'.format(s=str(e)))
                from server import Server
                Server.create(self.mode)
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

    def close(self):
        if not self.failed:
            return

        self.failed = False

    def load(self):
        IptcMain.logger.debug('loading data from server process')

        self.send('LOAD')

        data = []
        for line in self.recv():
            if line == 'OK':
                break

            if line.startswith('FAILURE/'):
                raise IPTCError(line[8:])

            data.append(line)

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
            'buffering {n} lines for table {name}...'.format(n=len(data), name=tblname))

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

    @classmethod
    def manager(cls, mode):
        if not hasattr(cls, 'serverstarted'):
            cls.serverstarted = {}

        if cls.serverstarted.get(mode) is None:
            from server import Server
            Server.create(mode)
            cls.serverstarted[mode] = True

        return Manager.MANAGERS.get(mode)


if __name__ == "__main__":
    IptcMain.setLogger(IptcLogger.create(MODULE_NAME, disk=False, debug=True))

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
