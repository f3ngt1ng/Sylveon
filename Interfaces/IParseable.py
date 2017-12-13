# -*- coding: UTF-8 -*-


import abc
import struct

from ProjectExceptions import KnownError


class IParseable(object, metaclass = abc.ABCMeta):
    @classmethod
    def parse_byte(cls, data):
        try:
            return struct.unpack("<B", data[:1])[0]
        except struct.error as e:
            raise KnownError(e)

    @classmethod
    def parse_word(cls, data):
        try:
            return struct.unpack("<H", data[:2])[0]
        except struct.error as e:
            raise KnownError(e)

    @classmethod
    def parse_dword(cls, data):
        try:
            return struct.unpack("<I", data[:4])[0]
        except struct.error as e:
            raise KnownError(e)

    @classmethod
    def parse_qword(cls, data):
        try:
            return struct.unpack("<Q", data[:8])[0]
        except struct.error as e:
            raise KnownError(e)

    @classmethod
    def parse_qword_be(cls, data):
        try:
            return struct.unpack(">Q", data[:8])[0]
        except struct.error as e:
            raise KnownError(e)

    @abc.abstractmethod
    def parse(self, data):
        raise NotImplementedError
