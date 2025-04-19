import functools
import os
import sys


def _warnmsg(warnmsg):
    print(f"WARNING: {warnmsg}", file=sys.stderr)


@functools.cache
def _cachedir():
    cachedir = os.getenv("XDG_CACHE_HOME")
    if cachedir:
        return cachedir
    return os.path.expanduser("~/.cache/badkeys/")
