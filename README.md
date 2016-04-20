# Pytables

Pytables is a (mostly) python-iptables drop-in replacement, intended to allow manipulation of netfilter rules/chains/tables directly by multiple processes,
communicating to a central server (pytables-server) which loads/stores rules using iptables-{restore,save}.

This library is implemented in pure-python and does not interface with C library libiptc - using libiptc directly is
[not recommended by netfilter development team](http://www.netfilter.org/documentation/FAQ/netfilter-faq-4.html#ss4.5) - thus eliminating
a number of issues arising from interface changes while staying compatible with different versions of iptables.

## API

The python-iptables interface have been followed as closely as possible, allowing programs written for this library to still work by doing:

~~~python
import pytables as iptc
~~~

However, a few extensions have been made on the original interface to ease programming, including the "iptc_command" decorator and the
ability to pass parameters as keyword arguments on object constructors.

### iptc_command

This decorator works in two stages, accepting a few keyword parameters in the first call (logger and maxretry), returning a decorator that accepts a generator.

The second decorator invocation returns a normal function that continuously iterates the generator until no more elements are yielded or some terminating action is performed.

For each type of yielded object (or special function called), a different action will be performed:

* Table object: will be placed in a list of objects to be commited;
* iptc_commit(): all previously yielded tables (and any other passed as argument) will be commited;
* iptc_abort(): transaction will be aborted and the function will return "None";
* iptc_return(r): value "r" will be returned from the function call invocation.

If any of the "commit" steps fail, the generator is restarted from the beginning.

The parameter "logger" allows passing a logger object (or lambda that returns a logger), and "maxretry" configures the amount
of times the generator is to be restarted (default of 5 attempts).

A small example of the decorator usage:

~~~python
from pytables import *
from pytables.helpers import *

@iptc_command()
def fn():
    table = Table("nat", autocommit=False)
    yield table
    # create rules
    iptc_commit()
    # create more rules
    iptc_commit()

    iptc_return(True) # return "True"

def main():
    res = fn()
    print res # prints "True"
~~~

The commit steps are not required, but may be useful to guarantee consistency on individual steps.

### Keyword arguments

`Rule`, `Target` and `Match` objects accept attributes as keyword arguments:

~~~python
rule = Rule()
m = Match(rule, 'udp', dport='1024:2048', sport='1234')
~~~

Which greatly simplifies coding of rules.

## Stability

This API is currently used in production, operating on IPv4 and IPv6 filter/nat tables simultaneously, performing changes on rules concurrently
with other processes (firewall, IDS, etc). Not all available combinations of rules/matches/options have been tested, though the library is
implemented in a generic way and should only need a few tweaks for combinations that introduce new logics for rule generation/processing.

## Compatibility

Most of the code was originally written in a way to keep compatibility with python2.[56], though most of the codebase is now using python2.7.

## License

Distributed under MPL 2.0 (see LICENSE file)

Copyright (C) 2014  Sangoma Technologies Corp.
