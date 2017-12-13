# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable
from Interfaces.IVerifiable import IVerifiable


class FILETIME(IParseable, IVerifiable):
    def __init__(self):
        self.LowDateTime = 0  # 4 bytes
        self.HighDateTime = 0  # 4 bytes

    def parse(self, data):
        index = 0

        self.LowDateTime = IParseable.parse_dword(data[index:])
        index += 4

        self.HighDateTime = IParseable.parse_dword(data[index:])
        index += 4

        return self

    def verify(self):
        return self.LowDateTime + self.HighDateTime != 0
