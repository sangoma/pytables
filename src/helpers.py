# Copyright (C) 2014  Sangoma Technologies Corp.
# All Rights Reserved.
#
# Author(s)
# Leonardo Lang <lang@sangoma.com>
#
# This modules provides a decorator and some helpful functions
# for simplifying code that uses iptc library by abstracting
# away the retry mechanism.

__all__ = [ 'iptc_return', 'iptc_commit', 'iptc_abort', 'iptc_command' ]

import time
from . import IPTCError, XTablesError

class IptcEmptyLogger(object):
    emptyLogger = None

    def error(x): pass
    def warning(x): pass
    def info(x): pass
    def debug(x): pass

IptcEmptyLogger.emptyLogger = IptcEmptyLogger()

class IptcAbort(Exception):
    pass

class IptcCommit(object):
    def __init__(self, *args):
        self.args = args

def iptc_return(data=None):
    raise StopIteration(data)

def iptc_commit(*args):
    return IptcCommit(*args)

def iptc_abort():
    raise IptcAbort()

def iptc_command(logger=None, maxretry=5):
    def innerbody(body):
        def getlogger():
            return logger() if callable(logger) else \
                (logger if logger is not None else \
                    IptcEmptyLogger.emptyLogger)

        def inner(self, *args, **kwargs):
            for numtry in xrange(maxretry):
                genbody = body(self, *args, **kwargs)
                tblcurr, tblsync = list(), list()
                tbl, got = None, False
                try:
                    while True:
                        for tbl in list(tblsync):
                            tbl.commit()
                            tblsync.remove(tbl)

                        tbl = None
                        obj = next(genbody)
                        got = True

                        if isinstance(obj, IptcCommit):
                            tbllst = tblcurr if len(obj.args) == 0 else obj.args
                            for tblref in tbllst:
                                if tblref in tblsync:
                                    continue
                                tblsync.append(tblref)
                            del tbllst[:]
                        else:
                            obj.restart()
                            if obj not in tblcurr:
                                tblcurr.append(obj)

                except (IPTCError, XTablesError) as e:
                    if tbl is not None:
                        getlogger().debug("commit failed on table {!s}: {!s}, retrying...".format(tbl, e))
                    else:
                        getlogger().debug("iptc operation failed: {!s}, retrying...".format(e))

                    time.sleep(0.05)

                except StopIteration as e:
                    if not got:
                        getlogger().warning('iptc function "{!s}" returned without commiting anything'.format(body.__name__))

                    try:
                        tbl = None
                        for tbl in list(tblcurr):
                            tbl.commit()

                    except (IPTCError, XTablesError) as e:
                        getlogger().debug("commit failed on table {!s}: {!s}, retrying...".format(tbl, e))
                        continue

                    try:
                        return e.args[0]
                    except:
                        return None

                except IptcAbort as e:
                    getlogger().debug('iptc function "{!s}" voluntarily aborted'.format(body.__name__))
                    return None
            else:
                getlogger().error('too many retries for iptc function "{!s}", aborting'.format(body.__name__))

        inner.__name__ = body.__name__
        inner.__doc__ = body.__doc__
        return inner

    innerbody.__name__ = iptc_command.__name__
    innerbody.__doc__ = iptc_command.__doc__
    return innerbody
