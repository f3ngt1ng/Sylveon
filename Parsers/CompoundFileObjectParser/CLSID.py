# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable
from Interfaces.IVerifiable import IVerifiable


class CLSID(IParseable, IVerifiable):
    def __init__(self):
        self.Data1 = 0  # 4 bytes
        self.Data2 = 0  # 2 bytes
        self.Data3 = 0  # 2 bytes
        self.Data4 = 0  # 8 bytes, big endian

    def parse(self, data):
        index = 0

        self.Data1 = IParseable.parse_dword(data[index:])
        index += 4

        self.Data2 = IParseable.parse_word(data[index:])
        index += 2

        self.Data3 = IParseable.parse_word(data[index:])
        index += 2

        self.Data4 = IParseable.parse_qword_be(data[index:])
        index += 8

        return self

    def verify(self):
        return self.Data1 + self.Data2 + self.Data3 + self.Data4 != 0

    def __str__(self):
        data1 = hex(self.Data1)[2:].ljust(8, "0")
        data2 = hex(self.Data2)[2:].ljust(4, "0")
        data3 = hex(self.Data3)[2:].ljust(4, "0")
        data4 = hex(self.Data4)[2:].ljust(16, "0")

        return "{data1}-{data2}-{data3}-{data4_1}-{data4_2}".format(
            data1 = data1,
            data2 = data2,
            data3 = data3,
            data4_1 = data4[:4],
            data4_2 = data4[4:]
        ).upper()
