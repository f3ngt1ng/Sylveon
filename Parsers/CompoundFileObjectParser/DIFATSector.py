# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable


class DIFATSectorEntry(IParseable):
    def __init__(self):
        self.SectorOffset = None

    def parse(self, data):
        self.SectorOffset = IParseable.parse_dword(data)

        return self


class DIFATSector(IParseable):
    def __init__(self):
        self.DIFATSectorEntries = []
        self.NextSectorID = None

    def parse(self, data):
        self.NextSectorID = IParseable.parse_dword(data[-4:])

        data = data[:-4]
        while len(data) > 0:
            self.DIFATSectorEntries.append(DIFATSectorEntry().parse(data))
            data = data[4:]

        return self
