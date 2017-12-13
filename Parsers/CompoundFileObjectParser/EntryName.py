# -*- coding: UTF-8 -*-


import string

from Interfaces.IParseable import IParseable
from Interfaces.IVerifiable import IVerifiable


class EntryName(IParseable, IVerifiable):
    def __init__(self):
        self.Data = None

    def parse(self, data):
        self.Data = data

    def verify(self):
        for char in self.Data:
            if chr(char) in ["\\", "/", ":", "!"]:
                return False

        if b"\x00\x00" not in self.Data:
            return False

        return True

    def __str__(self):
        result = ""

        for char in self.Data.decode("utf-16-le"):
            if char in string.printable:
                result += char
            else:
                result += "\\x{hex_value}".format(
                    hex_value = hex(ord(char))[2:].ljust(2, "0")
                )
                if ord(char) == 0:
                    break

        return result
