# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable


class FATSectorEntry(IParseable):
    def __init__(self):
        self.NextSectorID = None

    def parse(self, data):
        self.NextSectorID = IParseable.parse_dword(data)

        return self


class FATSector(IParseable):
    def __init__(self):
        self.FATSectorEntries = []

    def parse(self, data):
        while len(data) > 0:
            self.FATSectorEntries.append(FATSectorEntry().parse(data))
            data = data[4:]

        return self
