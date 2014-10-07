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

MODULE_NAME = 'pytables'

def pytables_socket(mode):
    return b'\0' + b'{b}-{m}.server'.format(b=MODULE_NAME, m=mode)

class IPTCError(Exception):

    def __init__(self, s=None):
        super(IPTCError, self).__init__(s)
        pass


class XTablesError(Exception):

    def __init__(self, s=None):
        super(XTablesError, self).__init__(s)
        pass


class IptcCache():

    @classmethod
    def load(cls, mode, lines, reloading=True, autoload=True):
        table = None

        if reloading:
            # clear rules
            for name, chain in Chain._cache.items():
                if chain.table.addrfamily != mode:
                    continue
                IptcMain.logger.debug(
                    'clearing chain {name}'.format(name=name))
                del chain._rules[:]

            # initialize control attribute
            for _, chain in Chain._cache.items():
                if chain.table.addrfamily != mode:
                    continue
                chain.valid = False

        for line in lines:
            stripline = line.strip()

            if stripline.startswith('#'):
                continue

            if stripline.startswith('*'):
                IptcMain.logger.debug(
                    'found table specification "{l}"'.format(l=stripline))

                table = IptcBaseTable(stripline[1:], mode, autoload=autoload)
                continue

            if stripline.startswith(':'):
                IptcMain.logger.debug(
                    'found chain specification "{l}"'.format(l=stripline))
                (chain_name, chain_policy, chain_stats) = shlex.split(
                    stripline[1:])

                if table is None:
                    IptcMain.logger.error(
                        'no table, cannot create chain "{name}"'.format(name=chain_name))
                    continue

                if chain_policy == '-':
                    chain_policy = None

                chain = Chain(table, chain_name, policy=chain_policy, autoload=autoload)
                for c in table._chains:
                    if chain.name == c.name:
                        break
                else:
                    table._chains.append(chain)

                if reloading:
                    IptcMain.logger.debug(
                        'chain {name} is valid'.format(name=chain_name))
                    chain.valid = True
                continue

            if stripline.startswith('-A'):
                IptcMain.logger.debug(
                    'found rule specification "{l}"'.format(l=stripline))

                rdata = shlex.split(stripline)
                chain = Chain(table, rdata[1], autoload=autoload)

                if chain is None:
                    IptcMain.logger.error(
                        'chain is none, cannot load rule "{l}"'.format(l=stripline))
                    continue

                try:
                    chain.deserialize(rdata[2:])
                except IPTCError, e:
                    IptcMain.logger.error(
                        'unable to parse chain {name}: {e}'.format(name=chain.name, e=str(e)))
                    raise

                continue

        if reloading:
            # scan control attribute and remove chains not valid
            for _, table in IptcBaseTable._cache.items():
                if table.addrfamily != mode:
                    continue
                remchains = []
                for chain in table._chains:
                    if chain.valid == False:  # dont change this
                        remchains.append(chain)
                for chain in remchains:
                    table._chains.remove(chain)

    @classmethod
    def save(cls, mode):
        res = []
        for _, table in IptcBaseTable._cache.items():
            if table.addrfamily != mode:
                continue
            IptcMain.logger.debug(
                'saving table {name}'.format(name=table.name))
            res.append('*' + table.name + '\n')
            res.extend(table.dump(eol='\n'))
        return res


class IptcLogger():

    @classmethod
    def create(cls, name, extra=None, disk=False, debug=False):
        svname = name if extra is None else name + '-' + extra
        logger = logging.getLogger(svname)

        if disk:
            handler = logging.handlers.RotatingFileHandler(
                '/var/log/{name}.log'.format(name=svname), maxBytes=1000000, backupCount=3)
            handler.setFormatter(
                logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'.format(mod=svname)))
            logger.addHandler(handler)
        else:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                logging.Formatter('{mod} %(levelname)s: %(message)s'.format(mod=svname)))
            logger.addHandler(handler)

        if debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        return logger

class IptcMain():
    logger = None
    debug = False

    @classmethod
    def setLogger(cls, logger):
        cls.logger = logger

    @classmethod
    def setDebug(cls, debug):
        cls.debug = debug
        if cls.logger is not None:
            cls.logger.setLevel(logging.DEBUG if debug else logging.INFO)

    @classmethod
    def initialize(cls, mode=None):
        if cls.logger is None:
            cls.setLogger(IptcLogger.create(MODULE_NAME, extra=mode, disk=True, debug=cls.debug))

# Internal base classes


class IptcBaseContainer(object):

    def __init__(self):
        self.exclude = set(self.__dict__.keys())

    def attributes(self, out):
        for key, val in self.__dict__.items():
            if key in self.exclude or key == 'exclude':
                continue
            param = key.replace('_', '-')

            IptcMain.logger.debug(
                'adding attribute "{k}" = "{v}"...'.format(k=param, v=val))

            outarg = '--{p}'.format(p=param)
            if len(val) != 0:
                if val[0] == '!':
                    out.extend(['!', outarg, val[2:]])
                else:
                    out.extend([outarg, val])
            else:
                out.append(outarg)

        return out


class IptcChainHook(object):
    def __init__(self, chain, valid):
        self.chain = chain
        self.valid = valid

    def run(self):
        IptcMain.logger.debug('HOOK: setting chain {name} valid = {v}'.format(
            name=self.chain.name, v=self.valid))
        self.chain.valid = self.valid


class IptcBaseTable(object):
    _cache = {}

    def __new__(cls, name, addrfamily, autocommit=False, autoload=True):
        IptcMain.initialize(addrfamily if not autoload else None)
        refer = addrfamily + '.' + name
        IptcMain.logger.debug(
            'checking cache for Table({r})'.format(r=refer))
        obj = IptcBaseTable._cache.get(refer, None)
        if obj is None:
            IptcMain.logger.debug(
                'no previous Table({r}) object, creating new...'.format(r=refer))
            obj = object.__new__(cls)
            obj.setup(name, addrfamily, autocommit)
            IptcBaseTable._cache[refer] = obj
        if autoload:
            IptcMain.logger.debug('requested autoload from Table({r})'.format(r=refer))
            from client import Manager
            Manager.manager(obj.addrfamily).resync()
        return obj

    def setup(self, name, addrfamily, autocommit=False):
        self._chains = []
        self.name = name
        self.addrfamily = addrfamily
        self.autocommit = autocommit
        self._manager = None

    def manager(self):
        if self._manager is None:
            from client import Manager
            self._manager = Manager.manager(self.addrfamily)
        return self._manager

    def update(self, data):
        self.manager().update(self.name, data)
        if self.autocommit:
            self.manager().save()

    chains = property(lambda s: list(s._chains))

    def restart(self):
        self.manager().resync()

    def resync(self):
        self.manager().resync()

    def commit(self):
        self.manager().save()

    def close(self):
        self.manager().close()

    def is_chain(self, chain):
        if isinstance(chain, str):
            chain = Chain(self, chain)

        if chain in self._chains:
            return chain.valid == True # could be None!

        return False

    def create_chain(self, chain):
        if isinstance(chain, str):
            chain = Chain(self, chain)

        IptcMain.logger.debug(
            'create_chain({name},valid={v})'.format(name=chain.name, v=str(chain.valid)))
        for cur in self._chains:
            if chain.name == cur.name:
                break
        else:
            self._chains.append(chain)

        if chain.valid == True:  # really, dont change this
            IptcMain.logger.debug(
                'chain already valid, skipping insert command')
            return

        out = ['-N {name}'.format(name=chain.name)]

        self.manager().update(self.name, out, hook=IptcChainHook(chain, True))
        if self.autocommit:
            self.manager().commit()
        return chain

    def delete_chain(self, chain):
        if isinstance(chain, str):
            chain = Chain(self, chain)

        IptcMain.logger.debug(
            'delete_chain({name},valid={v})'.format(name=chain.name, v=str(chain.valid)))
        for cur in self._chains:
            if chain.name == cur.name:
                self._chains.remove(cur)
                break

        if chain.valid == False:  # i'm serious, don't change it
            IptcMain.logger.debug('chain not valid, skipping remove command')
            return

        out = ['-X {name}'.format(name=chain.name)]

        self.manager().update(self.name, out, hook=IptcChainHook(chain, False))
        if self.autocommit:
            self.manager().commit()

    def load(self):
        self.manager.load()

    def dump(self, eol=''):
        res = []
        for chain in self._chains:
            pol = '-'
            if chain.policy is not None:
                pol = chain.policy
            res.append(':{name} {pol} [0:0]{eol}'.format(
                name=chain.name, pol=pol, eol=eol))
            res.extend(chain.dump(eol))
        return res

# External interface starts here


class Table(IptcBaseTable):

    def __new__(self, name, autocommit=False):
        return super(Table, self).__new__(Table, name, 'ipv4', autocommit)


class Table6(IptcBaseTable):

    def __new__(self, name, autocommit=False):
        return super(Table6, self).__new__(Table6, name, 'ipv6', autocommit)


class Chain(object):
    _cache = {}

    def __new__(cls, table, name, policy=None, autoload=True):
        refer = table.addrfamily + '.' + table.name + '.' + name
        IptcMain.logger.debug('checking cache for Chain({r})'.format(r=refer))
        obj = Chain._cache.get(refer, None)
        if obj is None:
            IptcMain.logger.debug('no previous Chain object, creating new...')
            obj = object.__new__(cls)
            obj.setup(table, name, policy)
            Chain._cache[refer] = obj
        if autoload:
            IptcMain.logger.debug('requested autoload from Chain({r})'.format(r=refer))
            from client import Manager
            Manager.manager(table.addrfamily).resync()
        return obj

    def setup(self, table, name, policy):
        IptcMain.logger.debug(
            'running init on Chain {name}...'.format(name=name))
        self._rules = []
        self.table = table
        self.name = name
        self.policy = policy
        self.valid = None

    def deserialize(self, rdata):
        attrmap = {
            '-s': 'src',           '--src': 'src',
            '-d': 'src',           '--dst': 'dst',
            '-i': 'in_interface',  '--in-interface':  'in_interface',
            '-o': 'out_interface', '--out-interface': 'out_interface',
            '-p': 'protocol',      '--protocol': 'protocol'
        }

        objopts = ['-m', '-j', '-g']

        IptcMain.logger.debug('processing rule data: {s}'.format(s=str(rdata)))

        rule = Rule()

        optind = 0
        revopt, revstr = False, ''

        while optind < len(rdata):
            IptcMain.logger.debug(
                'processing arg "{s}"'.format(s=rdata[optind]))

            attrdata = attrmap.get(rdata[optind])

            if attrdata is not None:
                if (optind + 1) == len(rdata):
                    raise IPTCError(
                        'missing value for option {k}'.format(k=attrdata))

                IptcMain.logger.debug('setting rule attr "{k}" = "{r}{v}"'.format(
                    r=revstr, k=attrdata, v=rdata[optind + 1]))
                setattr(rule, attrdata, revstr + rdata[optind + 1])
                optind += 2
                revopt, revstr = False, ''
                continue

            elif rdata[optind] in objopts:
                if (optind + 1) == len(rdata):
                    raise IPTCError(
                        'missing name for match/target/goto {name}'.format(name=rdata[optind]))

                offtind = optind + 2
                nextind = len(rdata) - offtind
                for nextopt in objopts:
                    try:
                        tmpind = rdata[offtind:].index(nextopt)
                        if tmpind < nextind:
                            nextind = tmpind
                    except:
                        pass

                nextind += offtind

                if rdata[optind] == '-m':
                    IptcMain.logger.debug('found match {r}{n} ({s}:{e})'.format(
                        r=revstr, n=rdata[optind + 1], s=optind, e=nextind))
                    obj = Match(rule, rdata[optind + 1], reverse=revopt)
                elif rdata[optind] == '-j':
                    IptcMain.logger.debug('found target {n} ({s}:{e})'.format(
                        r=revstr, n=rdata[optind + 1], s=optind, e=nextind))
                    obj = Target(rule, rdata[optind + 1])
                else:
                    IptcMain.logger.debug('found goto {n} ({s}:{e})'.format(
                        r=revstr, n=rdata[optind + 1], s=optind, e=nextind))
                    obj = Goto(rule, rdata[optind + 1])

                revopt, revstr = False, ''
                argind = offtind

                while argind < nextind:
                    arg = rdata[argind]
                    if arg.startswith('--'):
                        param = arg[2:].replace('-', '_')

                        if argind + 1 < nextind:
                            if not rdata[argind + 1].startswith('--'):
                                value = rdata[argind + 1]
                                argind += 2
                            else:
                                value = ''
                                argind += 1
                        else:
                            value = ''
                            argind += 1

                        IptcMain.logger.debug(
                            'setting object attribute "{k}" to "{r}{v}"'.format(r=revstr, k=param, v=value))
                        setattr(obj, param, revstr + value)
                        revopt, revstr = False, ''

                    elif arg == '!':
                        revopt, revstr = True, '! '
                        argind += 1

                    else:
                        IptcMain.logger.error(
                            'argument {a} in {l} unknown, skipping'.format(a=arg, l=str(rdata)))
                        argind += 1

                if rdata[optind] == '-m':
                    rule.add_match(obj)
                else:
                    rule.target = obj

                optind = nextind
                revopt, revstr = False, ''
                continue

            elif rdata[optind] == '!':
                revopt, revstr = True, '! '
                optind += 1

            else:
                raise IPTCError(
                    'unable to process option {name}'.format(name=rdata[optind]))

        IptcMain.logger.debug(
            'adding rule {n} to rule list...'.format(n=len(self._rules)))
        self._rules.append(rule)

    def rules(self):
        return self._rules

    rules = property(lambda s: list(s._rules))

    def insert_rule(self, rule, pos=None):
        IptcMain.logger.debug(
            'inserting rule {r}, pos {p}'.format(r=str(rule), p=str(pos)))

        tmp = []
        if rule not in self._rules:
            self._rules.append(rule)

            if pos is None:
                tmp.extend(['-A', self.name])
            else:
                tmp.extend(['-I', self.name, str(pos)])
        else:
            if pos is None:
                pos = self._rules.index(rule)

            tmp.extend(['-I', self.name, pos])

        tmp.append(rule.serialize())
        res = [' '.join(tmp)]
        IptcMain.logger.debug('saving Chain({res})'.format(res=res))
        self.table.update(res)

    def delete_rule(self, rule, pos=None):
        IptcMain.logger.debug(
            'deleting rule {r}, pos {p}'.format(r=str(rule), p=str(pos)))

        tmp = []
        if rule not in self._rules:
            if pos is None:
                tmp.extend(['-D', self.name])
                tmp.append(rule.serialize())
            else:
                tmp.extend(['-D', self.name, str(pos)])
        else:
            IptcMain.logger.debug('rules: {rs}'.format(rs=str(self._rules)))

            if pos is None:
                pos = self._rules.index(rule) + 1

            self._rules.remove(rule)

            tmp.extend(['-D', self.name, str(pos)])

        res = [' '.join(tmp)]
        IptcMain.logger.debug('deleting Chain({res})'.format(res=res))
        self.table.update(res)

    def flush(self):
        self._rules = []
        self.table.update(['-F {name}'.format(name=self.name)])

    def dump(self, eol=''):
        res = []
        for rule in self._rules:
            res.append(
                '-A {c} {r}{eol}'.format(c=self.name, r=rule.serialize(), eol=eol))
        return res


class Rule(IptcBaseContainer):

    def __init__(self):
        self.target = None
        self.matches = []

        # this should be the last line in init
        super(Rule, self).__init__()

    def serialize(self):
        if self.target is None:
            raise IPTCError('no target in rule')
        out = self.attributes([])
        for m in self.matches:
            out.append(m.serialize())
        out.append(self.target.serialize())
        res = ' '.join(out)
        IptcMain.logger.debug('serialize Rule({res})'.format(res=res))
        return res

    def add_match(self, match):
        self.matches.append(match)


class Rule6(Rule):
    pass


class Match(IptcBaseContainer):

    def __init__(self, rule, name, reverse=False):
        self.rule = rule
        self.name = name
        self.reverse = reverse

        # this should be the last line in init
        super(Match, self).__init__()

    def serialize(self):
        lst = ['-m', self.name]
        if self.reverse:
            lst.insert(0, '!')
        res = ' '.join(self.attributes(lst))
        IptcMain.logger.debug('serialize Match({res})'.format(res=res))
        return res


class Target(IptcBaseContainer):

    def __init__(self, rule, name):
        self.rule = rule
        self.name = name

        tmpname = str(name).upper()
        self.standard = tmpname != name

        rule.target = self

        # this should be the last line in init
        super(Target, self).__init__()

    def serialize(self):
        lst = ['-j', self.name]
        res = ' '.join(self.attributes(lst))
        IptcMain.logger.debug('Target({res})'.format(res=res))
        return res


class Goto(IptcBaseContainer):

    def __init__(self, rule, name):
        self.rule = rule
        self.name = name

        tmpname = str(name).upper()
        self.standard = tmpname != name

        rule.target = self

        # this should be the last line in init
        super(Goto, self).__init__()

    def serialize(self):
        lst = ['-g', self.name]
        res = ' '.join(self.attributes(lst))
        IptcMain.logger.debug('Goto({res})'.format(res=res))
        return res

# Debug function


def dump_current_cache():
    IptcMain.logger.info('-------- DUMPING CACHE BEGIN --------')
    for keyname, table in IptcBaseTable._cache.items():
        IptcMain.logger.info(
            'TABLE({af} {name} [{k}]'.format(af=table.addrfamily, name=table.name, k=keyname))

        for chain in table._chains:
            IptcMain.logger.info(
                '  CHAIN {name} {pol}'.format(name=chain.name, pol=str(chain.policy)))

            for rule in chain._rules:
                IptcMain.logger.info(
                    '    RULE: {r}'.format(r=rule.serialize()))

    IptcMain.logger.info('--------- DUMPING CACHE END ---------')