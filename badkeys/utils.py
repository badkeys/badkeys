import functools
import os
import sys

_retval = 0


@functools.cache
def _setret(rv):
    global _retval
    _retval |= rv


def _getret():
    return _retval


def _warnmsg(msg):
    _setret(2)
    print(f"WARNING: {msg}", file=sys.stderr)


def _errexit(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(_retval | 1)


@functools.cache
def _cachedir():
    cachedir = os.getenv("XDG_CACHE_HOME")
    if cachedir:
        return os.path.join(cachedir, "badkeys", "")
    return os.path.expanduser("~/.cache/badkeys/")
