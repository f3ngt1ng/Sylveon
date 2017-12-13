# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable
from Parsers.CompoundFileObjectParser.CLSID import CLSID
from Parsers.CompoundFileObjectParser.Constants import BLACK, NO_STREAM, RED, ROOT_STORAGE_OBJECT, STORAGE_OBJECT, \
    STREAM_OBJECT, UNKNOWN_OR_UNALLOCATED
from Parsers.CompoundFileObjectParser.EntryName import EntryName
from Parsers.CompoundFileObjectParser.FILETIME import FILETIME
from ProjectExceptions import KnownError


class DirectorySectorEntry(IParseable):
    def __init__(self):
        self.DirectoryEntryName = EntryName()
        self.DirectoryEntryNameLength = 0  # 2 bytes
        self.ObjectType = 0  # 1 byte
        self.ColorFlag = 0  # 1 byte
        self.LeftSiblingID = 0  # 4 bytes
        self.RightSiblingID = 0  # 4 bytes
        self.ChildID = 0  # 4 bytes
        self.CLSID = CLSID()
        self.StateBits = 0  # 4 bytes
        self.CreationTime = FILETIME()
        self.ModifiedTime = FILETIME()
        self.StartingSectorLocation = 0  # 4 bytes
        self.StreamSize = 0  # 8 bytes

    def parse(self, data):
        index = 0

        self.DirectoryEntryName.parse(data[index:index + 64])
        index += 64
        if not self.DirectoryEntryName.verify():
            raise KnownError("Invalid directory entry name.")

        # DirectoryEntryNameLength MUST be less than or equal with 64.
        self.DirectoryEntryNameLength = IParseable.parse_word(data[index:])
        index += 2
        if self.DirectoryEntryNameLength > 64:
            raise KnownError("Invalid directory entry name length.")

        # ObjectType MUST be 0x0, 0x1, 0x2 or 0x5.
        self.ObjectType = IParseable.parse_byte(data[index:])
        index += 1
        if self.ObjectType not in [UNKNOWN_OR_UNALLOCATED, STORAGE_OBJECT, STREAM_OBJECT, ROOT_STORAGE_OBJECT]:
            raise KnownError("Invalid object type.")

        # ColorFlag MUST be 0x0 or 0x1.
        self.ColorFlag = IParseable.parse_byte(data[index:])
        index += 1
        if self.ColorFlag not in [RED, BLACK]:
            raise KnownError("Invalid color flag.")

        self.LeftSiblingID = IParseable.parse_dword(data[index:])
        index += 4

        self.RightSiblingID = IParseable.parse_dword(data[index:])
        index += 4

        self.ChildID = IParseable.parse_dword(data[index:])
        index += 4

        # A stream object should not have a child.
        if self.ObjectType == STREAM_OBJECT and self.ChildID != NO_STREAM:
            raise KnownError("Invalid stream.")

        self.CLSID.parse(data[index:])
        index += 16

        # A stream object should not have a CLSID.
        if self.ObjectType == STREAM_OBJECT and self.CLSID.verify():
            raise KnownError("Invalid stream.")

        self.StateBits = IParseable.parse_dword(data[index:])
        index += 4

        self.CreationTime.parse(data[index:])
        index += 8

        self.ModifiedTime.parse(data[index:])
        index += 8

        # A stream object should not have a CreationTime or ModifiedTime.
        if self.ObjectType == STREAM_OBJECT:
            if self.CreationTime.verify() or self.ModifiedTime.verify():
                raise KnownError("Invalid stream.")

        self.StartingSectorLocation = IParseable.parse_dword(data[index:])
        index += 4

        # TODO: stream size should be checked(major version 3)
        self.StreamSize = IParseable.parse_qword(data[index:])
        index += 8

        return self


class DirectorySector(IParseable):
    def __init__(self):
        self.DirectorySectorEntries = []

    def parse(self, data):
        while len(data) > 0:
            self.DirectorySectorEntries.append(DirectorySectorEntry().parse(data))
            data = data[128:]

        return self
