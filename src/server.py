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

from . import IptcMain, IptcLogger, IptcCache, IPTCError, pytables_socket

MODULE_NAME = 'pytables-daemon'

class WorkerInstance(object):

    def __init__(self, mode, save=None, load=None):
        self.mode = mode
        self.cmdsave = save
        self.cmdload = load
        self.failed = False
        self.loaded = False
        self.proc = None
        self.line = 0

    def restart(self):
        self.close()
        self.load()
        self.start()

    def load(self):
        if self.loaded:
            return True
        IptcMain.logger.debug(
            'worker loading from "{name}"...'.format(name=self.cmdload[0]))
        try:
            loadproc = subprocess.Popen(
                self.cmdload, bufsize=0, stdout=subprocess.PIPE)
            data = loadproc.communicate()[0].splitlines()
            IptcCache.load(self.mode, data, autoload=False)
        except:
            return str(sys.exc_info()[1])
        return None

    def start(self):
        if self.proc is not None:
            return

        IptcMain.logger.debug(
            'restarting process "{name}"...'.format(name=self.cmdsave[0]))
        try:
            self.proc = subprocess.Popen(
                self.cmdsave, bufsize=0, stdin=subprocess.PIPE)
        except:
            raise IPTCError('unable to spawn "{name}": {e}'.format(
                name=self.cmdsave[0], e=str(sys.exc_info()[1])))

    def close(self, failed=False):
        self.line = 0

        self.failed = failed
        self.loaded = False

        if self.proc is None:
            return

        IptcMain.logger.debug('closing process "{name}" (pid={pid})...'.format(
            name=self.cmdsave[0], pid=self.proc.pid))
        self.proc.stdin.flush()
        self.proc.stdin.close()
        retcode = self.proc.wait()
        if retcode != 0:
            IptcMain.logger.info(
                'process "{name}" returned {ret}\n'.format(name=self.cmdsave[0], ret=retcode))

        self.proc = None

    def save(self, data):
        self.start()

        IptcMain.logger.debug(
            'worker({mode}) storing rules...'.format(mode=self.mode))

        def poutput(s, flush=False, dup=None):
            self.line += 1
            IptcMain.logger.debug('worker({mode},{line:03d}) writing: {data}'.format(
                mode=self.mode, line=self.line, data=s))
            sdata = s + '\n'
            self.proc.stdin.write(sdata)
            if dup is not None:
                dup.append(sdata)
            if flush:
                self.proc.stdin.flush()
            return sdata

        duplines = []
        for tname, lines in data.items():
            try:
                poutput('*' + tname, dup=duplines)
                for ln in lines:
                    poutput(ln, dup=duplines)
                poutput('COMMIT', flush=True, dup=duplines)
                poutput('# COMMIT VALIDATION', flush=True)

            except:
                self.close(failed=True)
                return str(sys.exc_info()[1])

        # now apply changes to current cache
        IptcMain.logger.debug(
            'worker({mode}) loading changes...'.format(mode=self.mode))
        IptcCache.load(self.mode, duplines, reloading=False, autoload=False)
        IptcMain.logger.debug('worker({mode}) done'.format(mode=self.mode))

        return None


class Worker():
    WORKERS = {
        'ipv4': WorkerInstance('ipv4', save=['/sbin/iptables-restore', '-n'], load=['/sbin/iptables-save']),
        'ipv6': WorkerInstance('ipv6', save=['/sbin/ip6tables-restore', '-n'], load=['/sbin/ip6tables-save'])
    }

    @classmethod
    def worker(cls, mode):
        return Worker.WORKERS.get(mode)


class ConnectionBaseState(object):

    def __init__(self):
        self.transitions = None

    def load(self, states):
        IptcMain.logger.debug(
            'no transition loaded for state "{n}"'.format(n=self.__class__.__name__))
        self.transitions = {}

    def handle(self, c, msg):
        raise StopIteration(False)
        yield

    def running(self, c):
        return
        yield

    def process(self, c, msg):
        if self.transitions is None:
            self.load(c.state)

        IptcMain.logger.debug(
            '{n}({p}) calling handler'.format(n=self.__class__.__name__, p=c.pid))
        ret = yield self.handle(c, msg)

        m = self.transitions.get(msg)

        if m is not None:
            IptcMain.logger.debug('{o}({p}) transition to state "{n}"'.format(
                o=self.__class__.__name__, n=m.__class__.__name__, p=c.pid))
            c.state.current = m
            yield m.running(c)

        raise StopIteration(ret)


class ConnectionStateVoid(ConnectionBaseState):

    def __init__(self):
        super(ConnectionStateVoid, self).__init__()

    def load(self, states):
        self.transitions = {'LOAD': states.load}

    def handle(self, c, msg):
        retr = False
        if msg == 'SAVE':
            yield c.send('FAILURE/current state is out-of-date')
            retr = True

            IptcMain.logger.debug('{c}({pid}) handle(SAVE) = FAILURE'.format(pid=c.pid,
                                                                             c=self.__class__.__name__))

        raise StopIteration(retr)


class ConnectionStateSync(ConnectionBaseState):

    def __init__(self):
        super(ConnectionStateSync, self).__init__()

    def load(self, states):
        self.transitions = {
            'LOAD': states.load,
            'SAVE': states.save
        }


class ConnectionStateLoad(ConnectionBaseState):

    def __init__(self):
        super(ConnectionStateLoad, self).__init__()

    def running(self, c):
        ret = Worker.worker(c.mode).load()

        if ret is not None:
            res = 'FAILURE/' + ret
        else:
            data = IptcCache.save(c.mode)

            IptcMain.logger.debug('{c}({pid}) running(), sending {n} lines'.format(pid=c.pid,
                                                                                   c=self.__class__.__name__, n=len(data)))

            yield c.sendbuffer(data)
            res = 'OK'

        yield c.send(res)

        c.state.current = c.state.sync
        raise StopIteration()


class ConnectionStateSave(ConnectionBaseState):

    def __init__(self):
        self.data = {}
        self.curr = None
        super(ConnectionStateSave, self).__init__()

    def load(self, states):
        self.transitions = {'COMMIT': states.sync}

    def handle(self, c, msg):
        retr = False
        if msg == 'COMMIT':
            ret = Worker.worker(c.mode).save(self.data)
            if ret is None:
                res = 'OK'
            else:
                res = 'FAILURE/{ret}'.format(ret=ret)

            yield c.send(res)

            IptcMain.logger.debug('{c}({pid}) handle(COMMIT) = {res}'.format(pid=c.pid,
                                                                             c=self.__class__.__name__, res=res))

            self.data = {}
            retr = True

        elif msg.startswith('TABLE/'):
            self.curr = msg[6:]
            self.data[self.curr] = []

        elif self.curr is not None:
            self.data[self.curr].append(msg)

        raise StopIteration(retr)
        yield

    def running(self, c):
        self.data = {}
        self.curr = None
        raise StopIteration()
        yield


class ConnectionState():

    def __init__(self):
        self.void = ConnectionStateVoid()
        self.sync = ConnectionStateSync()
        self.load = ConnectionStateLoad()
        self.save = ConnectionStateSave()
        self.current = self.void


class Connection():

    def __init__(self, mode, conn, pid):
        self.mode = mode
        self.stream = mt.Stream(conn)
        self.pid = pid
        self.state = ConnectionState()
        IptcMain.logger.debug(
            'client({mode},{pid}) new client instance'.format(mode=self.mode, pid=self.pid))

    def send(self, data):
        yield self.sendbuffer(data + '\n')

    def sendbuffer(self, data):
        strdata = ''.join(data)
        IptcMain.logger.debug('client({mode},{pid}) sending {n} lines of data'.format(
            mode=self.mode, pid=self.pid, n=len(data)))
        yield self.stream.write(strdata)

    def process(self, message, daemon):
        if (yield self.state.current.process(self, message)):
            daemon.reloaded(self)

    def run(self, daemon):
        IptcMain.logger.debug(
            'client({mode},{pid}) client running'.format(mode=self.mode, pid=self.pid))
        try:
            while True:
                IptcMain.logger.debug(
                    'client({mode},{pid}) waiting for data...'.format(mode=self.mode, pid=self.pid))
                data = yield self.stream.read_until(ch='\n')
                if data is None:
                    break  # log something?
                IptcMain.logger.debug('client({mode},{pid}) processing message: {m}'.format(
                    mode=self.mode, pid=self.pid, m=data))
                yield self.process(data, daemon)

        except socket.error as e:
            if e[0] != errno.EBADF and e[0] != errno.ECONNRESET and e[0] != errno.EPIPE:
                raise
        finally:
            IptcMain.logger.debug(
                'client({mode},{pid}) bailing out...'.format(mode=self.mode, pid=self.pid))
            daemon.disconnect(self)

        raise StopIteration()


class ServerAlreadyRunning(Exception):
    pass


class Server():

    @classmethod
    def create(cls, mode):
        try:
            Server(mode).start()
        except ServerAlreadyRunning:
            IptcMain.logger.info('daemon already running, not starting')
        except:
            IptcMain.logger.warning(
                'could not start daemon: {e}'.format(e=str(sys.exc_info()[1])))

    def __init__(self, mode):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(pytables_socket(mode))
            sock.listen(5)
            sock.setblocking(0)
        except socket.error as e:
            if e[0] == errno.EADDRINUSE:
                raise ServerAlreadyRunning()
            raise

        self.mode = mode
        self.sock = sock
        self.tasks = None

    def start(self):
        pid = os.fork()

        if pid == 0:
            pid2 = os.fork()

            if pid2 == 0:
                try:
                    nilrd = open(os.devnull)
                    nilwr = open(os.devnull, 'w')
                    os.dup2(nilrd.fileno(), 0)
                    os.dup2(nilwr.fileno(), 1)
                    os.dup2(nilwr.fileno(), 2)
                    os.setsid()
                    # now setup and run
                    self.setup()
                    os._exit(self.main())
                except:
                    traceback.print_exc(file=sys.stderr)
                    os._exit(123)
            else:
                os._exit(0)
        else:
            os.close(self.sock.fileno())
            os.waitpid(pid, 0)

    def cloexec(self, sock):
        sockflags = fcntl.fcntl(sock, fcntl.F_GETFD)
        fcntl.fcntl(sock, fcntl.F_SETFD, sockflags | fcntl.FD_CLOEXEC)

    def setup(self, extra=None, disk=True, debug=False):
        IptcMain.setLogger(IptcLogger.create(MODULE_NAME,
            extra=self.mode if extra is None else extra,
            disk=disk, debug=debug))

    def log(self, msg, debug=True):
        data = 'daemon({mode},{pid}) {msg}'.format(
            mode=self.mode, pid=os.getpid(), msg=msg)
        if debug:
            IptcMain.logger.debug(data)
        else:
            IptcMain.logger.info(data)

    def main(self):
        self.tasks = mt.TaskManager()
        self.cloexec(self.sock)
        self.tasks.add(self.run())
        self.tasks.run()
        return 0

    def run(self):
        self.clients = set()

        self.log('listening...', debug=False)
        try:
            while True:
                kwargs = {}
                if len(self.clients) == 0:
                    kwargs['timeout'] = 5
                conn, addr = (yield mt.accept(self.sock, **kwargs))

                # socket.SO_PEERCRED = 17, sizeof(struct ucred) = 24
                buffdata = conn.getsockopt(socket.SOL_SOCKET, 17, 24)
                (pid, uid, gid) = struct.unpack('III', buffdata)

                self.log('connection from PID {p} (uid={u}, gid={g})'.format(
                    p=pid, u=uid, g=gid), debug=False)

                client = Connection(self.mode, conn, pid)
                self.connect(client, conn)
                yield client.run(self)
        except socket.error as e:
            if e[0] != errno.EBADF:
                raise
        except mt.Timeout:
            self.log('timeout waiting for clients', debug=False)
        finally:
            self.log('terminated')
            self.cleanup()

    def reloaded(self, client):
        self.log('reload request from client PID {p}'.format(p=client.pid))
        for oclient in self.clients:
            if client == oclient:
                continue
            oclient.state.current = client.state.void

    def connect(self, client, conn):
        self.clients.add(client)
        # avoid issues with stuck descriptors
        self.cloexec(conn)

    def disconnect(self, client):
        if client in self.clients:
            self.clients.remove(client)

        if len(self.clients) == 0:
            self.log('no clients left, starting timeout', debug=False)

    def cleanup(self):
        for client in self.clients:
            try:
                client.stream.val.shutdown(socket.SHUT_RDWR)
            except:
                pass

        try:
            self.sock.close()
        except:
            pass
