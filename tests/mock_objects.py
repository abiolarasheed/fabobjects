# !*-* coding:utf-8 *-*
from __future__ import unicode_literals
# Taken from https://prmtl.net/post/mocking-stdout-in-tests and add python 3 support

"""
Stand-alone stream mocking decorator for easier imports.
"""
import mock
import sys

try:
    from StringIO import StringIO  # No need for cStringIO at this time
except ImportError:
    from io import StringIO


class CCStringIO(StringIO):
    """A "carbon copy" StringIO.

    It's capable of multiplexing its writes to other buffer objects.

    Taken from fabric.tests.mock_streams.CarbonCopy
    """

    def __init__(self, buffer='', writers=None):
        """Init CCStringIO

        If ``writers`` is given and is a file-like object or an
        iterable of same, it/they will be written to whenever this
        StringIO instance is written to.
        """
        StringIO.__init__(self, buffer)
        if writers is None:
            writers = []
        elif hasattr(writers, 'write'):
            writers = [writers]
        self.writers = writers

    def write(self, s):
        # unfortunately, fabric writes into StringIO both so-called
        # bytestrings and unicode strings. obviously, bytestrings may
        # contain non-ascii symbols. that leads to type-conversion
        # issue when we use string's join (inside getvalue()) with
        # a list of both unicodes and bytestrings. in order to avoid
        # this issue we should convert all input unicode strings into
        # utf-8 bytestrings (let's assume that slaves encoding is utf-8
        # too so we won't have encoding mess in the output file).
        if isinstance(s, unicode):
            s = s.encode('utf-8')

        StringIO.write(self, s)
        for writer in self.writers:
            writer.write(s)


def mock_stdout():
    """Returns mock of sys.stdout with proxy to actual sys.stdout"""
    return mock.patch(
        'sys.stdout',
        new=CCStringIO(writers=[sys.__stdout__])
    )
