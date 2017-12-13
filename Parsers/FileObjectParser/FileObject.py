# -*- coding: UTF-8 -*-


import hashlib
import os

from ProjectExceptions import KnownError


class FileObject(object):
    def __init__(self, file_name = None):
        self.file_name = file_name

        self.md5 = None
        self.sha1 = None
        self.sha256 = None

        if file_name:
            self.update()

    def update(self):
        text = self.read()

        md5_context = hashlib.md5()
        md5_context.update(text)
        self.md5 = md5_context.hexdigest()

        sha1_context = hashlib.sha1()
        sha1_context.update(text)
        self.sha1 = sha1_context.hexdigest()

        sha256_context = hashlib.sha256()
        sha256_context.update(text)
        self.sha256 = sha256_context.hexdigest()

        return self

    def read(self):
        text = b""

        try:
            with open(self.file_name, "rb") as f:
                text = f.read()
        except (TypeError, FileNotFoundError, IOError) as e:
            raise KnownError(e)

        return text

    def write(self, data, mode = "wb"):
        try:
            with open(self.file_name, mode) as f:
                f.write(data)
        except (TypeError, FileNotFoundError, IOError) as e:
            raise KnownError(e)

    def append(self, data):
        return self.write(data = data, mode = "ab")

    def rename(self, new_name):
        try:
            os.rename(src = self.file_name, dst = new_name)
            self.file_name = new_name
        except (TypeError, FileNotFoundError, OSError) as e:
            raise KnownError(e)

    def move_to(self, new_directory):
        if os.path.isdir(new_directory):
            self.rename(os.path.join(new_directory, os.path.split(self.file_name)[-1]))
        else:
            raise KnownError("{d} is not a valid directory.".format(d = new_directory))
