# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable
from Interfaces.IVerifiable import IVerifiable
from Parsers.CompoundFileObjectParser.CLSID import CLSID
from ProjectExceptions import KnownError


class CompoundFileHeader(IParseable, IVerifiable):
    def __init__(self):
        self.HeaderSignature = 0  # 8 bytes, big endian
        self.HeaderCLSID = CLSID()
        self.MinorVersion = 0  # 2 bytes
        self.MajorVersion = 0  # 2 bytes
        self.ByteOrder = 0  # 2 bytes
        self.SectorShift = 0  # 2 bytes
        self.MiniSectorShift = 0  # 2 bytes
        self.Reserved1 = 0  # 2 bytes
        self.Reserved2 = 0  # 4 bytes
        self.NumberOfDirectorySectors = 0  # 4 bytes
        self.NumberOfFATSectors = 0  # 4 bytes
        self.FirstDirectorySectorLocation = 0  # 4 bytes
        self.TransactionSignatureNumber = 0  # 4 bytes
        self.MiniStreamCutoffSize = 0  # 4 bytes
        self.FirstMiniFATSectorLocation = 0  # 4 bytes
        self.NumberOfMiniFATSectors = 0  # 4 bytes
        self.FirstDIFATSectorLocation = 0  # 4 bytes
        self.NumberOfDIFATSectors = 0  # 4 bytes
        self.DIFAT = 0  # 436 bytes(first 109 FAT sector locations)

    def parse(self, data):
        index = 0

        # HeaderSignature MUST be 0xD0CF11E0A1B11AE1.
        self.HeaderSignature = IParseable.parse_qword_be(data[index:])
        index += 8
        if not self.verify():
            raise KnownError("Invalid header signature.")

        self.HeaderCLSID.parse(data[index:])
        index += 16

        # MinorVersion SHOULD be 0x3E.
        self.MinorVersion = IParseable.parse_word(data[index:])
        index += 2
        if self.MinorVersion != 0x3E:
            raise KnownError("Invalid minor version.")

        # MajorVersion MUST be 0x3 or 0x4.
        self.MajorVersion = IParseable.parse_word(data[index:])
        index += 2
        if self.MajorVersion not in [0x3, 0x4]:
            raise KnownError("Invalid major version.")

        # ByteOrder MUST be 0xFFFE(little endian).
        self.ByteOrder = IParseable.parse_word(data[index:])
        index += 2
        if self.ByteOrder != 0xFFFE:
            raise KnownError("Invalid byteorder.")

        # SectorShift MUST be 0x9(version 3) or 0xC(version 4).
        self.SectorShift = IParseable.parse_word(data[index:])
        index += 2
        if self.MajorVersion == 0x3 and self.SectorShift != 0x9:
            raise KnownError("Invalid sector shift.")
        if self.MajorVersion == 0x4 and self.SectorShift != 0xC:
            raise KnownError("Invalid sector shift.")

        # MiniSectorShift MUST be 0x6.
        self.MiniSectorShift = IParseable.parse_word(data[index:])
        index += 2
        if self.MiniSectorShift != 0x6:
            raise KnownError("Invalid mini sector shift.")

        # Reserved1 and Reserved2 MUST be 0x0.
        self.Reserved1 = IParseable.parse_word(data[index:])
        index += 2
        self.Reserved2 = IParseable.parse_dword(data[index:])
        index += 4
        if self.Reserved1 + self.Reserved2 != 0x0:
            raise KnownError("Invalid reserved value.")

        # NumberOfDirectorySectors MUST be 0x0 if Major Version is 3.
        self.NumberOfDirectorySectors = IParseable.parse_dword(data[index:])
        index += 4
        if self.MajorVersion == 0x3 and self.NumberOfDirectorySectors != 0x0:
            raise KnownError("Invalid number of directory sectors.")

        self.NumberOfFATSectors = IParseable.parse_dword(data[index:])
        index += 4

        self.FirstDirectorySectorLocation = IParseable.parse_dword(data[index:])
        index += 4

        self.TransactionSignatureNumber = IParseable.parse_dword(data[index:])
        index += 4

        # MiniStreamCutoffSize MUST be 0x1000.
        self.MiniStreamCutoffSize = IParseable.parse_dword(data[index:])
        index += 4
        if self.MiniStreamCutoffSize != 0x1000:
            raise KnownError("Invalid mini stream cutoff size.")

        self.FirstMiniFATSectorLocation = IParseable.parse_dword(data[index:])
        index += 4

        self.NumberOfMiniFATSectors = IParseable.parse_dword(data[index:])
        index += 4

        self.FirstDIFATSectorLocation = IParseable.parse_dword(data[index:])
        index += 4

        self.NumberOfDIFATSectors = IParseable.parse_dword(data[index:])
        index += 4

        self.DIFAT = data[index:index + 4 * 109]
        index += 4 * 109

        # The remaining part of the header MUST be filled with all zeroes.
        for value in data[index:2 ** self.SectorShift]:
            if value != 0:
                raise KnownError("Invalid header.")

        return self

    def verify(self):
        return self.HeaderSignature == 0xD0CF11E0A1B11AE1
