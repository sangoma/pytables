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
import threading
import signal

from . import IptcMain, IptcCache, IPTCError, pytables_socket, debugcall

MODULE_NAME = 'pytables-client'
CONFIG_NAME = '/etc/pytables/clients.conf'

class AlarmTimeout():
    pass

def raise_alarm(sig, frame):
    raise AlarmTimeout()

def setup_alarm(timeout):
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, raise_alarm)

    current_time = time.time()

    previous_timeout = signal.alarm(timeout)

    return (previous_handler, previous_timeout, current_time)

def clear_alarm(data):
    (previous_handler, previous_timeout, previous_time) = data

    signal.alarm(0)
    signal.signal(signal.SIGALRM, previous_handler)

    if previous_timeout != 0:
        current_time = time.time()
        current_timeout = int(previous_timeout - (current_time - previous_time))
        signal.alarm(1 if current_timeout <= 0 else current_timeout)

class LineRecvBuffer():

    def __init__(self):
        self.buff = ''

    def recv(self, sock, number=None, timeout=8):
        pos, cur, lst = 0, 0, []

        IptcMain.logger.debug('receiving data from server')
        for attempt in range(0, 5):
            alarm_data = setup_alarm(timeout)
            try:
                res = sock.recv(4096)
                break

            except AlarmTimeout as e:
                raise IPTCError('timeout waiting for response from server')

            except socket.error as e:
                if e.errno != errno.EINTR:
                    raise
                IptcMain.logger.warning(
                    'recv failed: {s}, trying again...'.format(s=str(e)))
                time.sleep(0.5)

            finally:
                clear_alarm(alarm_data)
        else:
            raise IPTCError('too many failed recv attempts, giving up')

        if len(res) == 0:
            raise IPTCError('connection closed')

        self.buff += res
        while pos < len(self.buff) and (len(lst) < number if number else True):
            cur = self.buff.find('\n', pos)
            if cur == -1:
                break
            lst.append(self.buff[pos:cur])
            pos = cur + 1

        if pos != 0:
            self.buff = self.buff[pos:]

        IptcMain.logger.debug('responses from server: {s}'.format(s=', '.join(lst)))
        return lst


class ManagerInstance(object):

    def __init__(self, mode):
        self.loaded = False
        self.failed = False

        self.mode = mode
        self.sock = None

        self.request = 0

        self.recv_buffer = LineRecvBuffer()
        self.save_buffer = {}
        self.chain_hooks = {}

        self.lock = threading.Lock()

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
        self.sendbuffer(data, nl=True)

    def sendformat(self, msg):
        ret = '{n:03x} {s}'.format(s=msg,n=self.request)
        self.request = (self.request + 1) % 0x1000
        return ret

    def sendbuffer(self, data, nl=True):
        newline = '\n' if nl else ''
        data = map(self.sendformat, data) if isinstance(data, list) else self.sendformat(data)
        strdata, strlines = (newline.join(data) + newline, len(data)) \
            if isinstance(data, list) else (data + newline, 1)
        IptcMain.logger.debug(
            '({mode}) buffering {n} lines'.format(mode=self.mode, n=strlines))
        self.sock.send(strdata)

    def process(self, data):
        res = list()
        for line in data:
            IptcMain.logger.debug('processing message: {m}'.format(m=line))
            msgdata = line.split(' ', 1)
            if len(msgdata) == 2:
                res.append(msgdata[1])
            else:
                IptcMain.logger.warning('ignoring message with wrong format: {m}'.format(m=line))
        return res

    def recv(self, number=None):
        if self.sock is None:
            self.start()

        return self.process(self.recv_buffer.recv(self.sock, number))

    def restart(self, force=True):
        self.resync(force=force)

    def resync(self, force=False):
        IptcMain.logger.debug('requested manager resync (force={f!s})'.format(f=force))

        try:
            self.lock.acquire()

            if force:
                self.reboot(locked=False)

            if not self.loaded:
                self.load(locked=False)
                self.loaded = True
            else:
                self.load(force=False, locked=False)
        finally:
            self.lock.release()

    def close(self):
        if not self.failed:
            return

        self.failed = False

    def reboot(self, locked=True):
        IptcMain.logger.debug('sending reboot request to server process')

        try:
            if locked:
                self.lock.acquire()

            self.send('BOOT')

            msgdata = self.recv(number=1)[0]

            if msgdata.startswith('FAILURE/'):
                raise IPTCError(msgdata[8:])
            if msgdata != 'OK':
                raise IPTCError('unknown reply: {s}'.format(s=msgdata))
        finally:
            if locked:
                self.lock.release()

    @debugcall
    def load(self, force=True, locked=True):
        try:
            if locked:
                self.lock.acquire()

            self.send('LOAD' if force else 'SYNC')

            data, okey = [], False

            while not okey:
                for line in self.recv():
                    IptcMain.logger.debug('{mode} received: {data}'.format(mode=self.mode,data=line))

                    if line == 'OK':
                        okey = True
                        break

                    if line.startswith('FAILURE/'):
                        raise IPTCError(line[8:])

                    data.append(line)

            if okey and len(data) == 0:
                return

            IptcCache.load(self.mode, data, autoload=False)

        finally:
            if locked:
                self.lock.release()

    @debugcall
    def update(self, tblname, data, hook=None):
        self.lock.acquire()

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

        self.lock.release()

    @debugcall
    def save(self):
        loop = True

        try:
            self.lock.acquire()

            for (tblname, data) in self.save_buffer.items():
                try:
                    self.send('SAVE')
                    self.sendbuffer('TABLE/' + tblname)
                    self.sendbuffer(data)
                    self.sendbuffer('COMMIT')

                    msgdata = self.recv(number=1)[0]
                    if msgdata.startswith('FAILURE/'):
                        raise IPTCError(msgdata[8:])
                    if msgdata != 'OK':
                        raise IPTCError('unknown reply: {s}'.format(s=msgdata))

                    hooks = self.chain_hooks.get(tblname)
                    if hooks is not None:
                        for hook in hooks:
                            hook.run()

                except IOError, e:
                    self.loaded = False
                    self.failed = True
                    raise IPTCError(str(e))

                except IPTCError, e:
                    self.loaded = False
                    self.failed = True
                    raise

        finally:
            self.save_buffer = {}
            self.lock.release()


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
