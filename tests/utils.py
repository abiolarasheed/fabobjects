# coding: utf-8
from __future__ import with_statement

import hashlib

from fabric.contrib.files import _expand_path


def fake_sudo(command, *args, **kwargs):
    """
    Command for faking sudo calls to avoid local/remote ssh call or local file system operations.
    :param command:
    :param args:
    :param kwargs:
    :return:
    """
    return command


def fake_run(command, *args, **kwargs):
    """
    Command for faking run calls to avoid local/remote ssh call or local file system operations.
    :param command:
    :param args:
    :param kwargs:
    :return:
    """
    return command


def fake_local(command, *args, **kwargs):
    """
    Command for faking local calls to avoid local file system operations.
    :param command:
    :param args:
    :param kwargs:
    :return:
    """
    return command


def fake_sed(
    filename,
    before,
    after,
    limit="",
    use_sudo=False,
    backup=".bak",
    flags="",
    shell=False,
):
    """
    Command for faking sed command to avoid local/remote ssh call or local file system operations.
    :param filename:
    :param before:
    :param after:
    :param limit:
    :param use_sudo:
    :param backup:
    :param flags:
    :param shell:
    :return:
    """

    func = use_sudo and fake_sudo or fake_run
    # Characters to be escaped in both
    for char in "/'":
        before = before.replace(char, r"\%s" % char)
        after = after.replace(char, r"\%s" % char)
    # Characters to be escaped in replacement only (they're useful in regexen
    # in the 'before' part)
    for char in "()":
        after = after.replace(char, r"\%s" % char)
    if limit:
        limit = r"/%s/ " % limit
    context = {
        "script": r"'%ss/%s/%s/%sg'" % (limit, before, after, flags),
        "filename": _expand_path(filename),
        "backup": backup,
    }
    # Test the OS because of differences between sed versions

    platform = fake_run("uname")

    if platform in ("NetBSD", "OpenBSD", "QNX"):
        hasher = hashlib.sha1()
        hasher.update("test.example.com")
        hasher.update(filename)
        context["tmp"] = "/tmp/%s" % hasher.hexdigest()
        # Use temp file to work around lack of -i
        expr = r"""cp -p %(filename)s %(tmp)s && sed -r -e %(script)s %(filename)s > %(tmp)s && cp -p %(filename)s
         %(filename)s%(backup)s && mv %(tmp)s %(filename)s"""
    else:
        context["extended_regex"] = "-E" if platform == "Darwin" else "-r"
        expr = r"sed -i%(backup)s %(extended_regex)s -e %(script)s %(filename)s"
    command = expr % context
    return func(command, shell=shell)


class TestServerHostManager(object):
    """A descriptor decorator useful for placing ServerHostManager for testing purpose."""

    def __init__(self, instance_method):
        self.func = instance_method
        self.func.__name__ = instance_method.__name__

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            result = self.func(instance, *args, **kwargs)
            return result

        wrapper.__name__ = self.func.__name__
        return wrapper
