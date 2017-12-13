# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable


class MiniFATSectorEntry(IParseable):
    def __init__(self):
        self.NextSectorID = None

    def parse(self, data):
        self.NextSectorID = IParseable.parse_dword(data)

        return self


class MiniFATSector(IParseable):
    def __init__(self):
        self.MiniFATSectorEntries = []

    def parse(self, data):
        while len(data) > 0:
            self.MiniFATSectorEntries.append(MiniFATSectorEntry().parse(data))
            data = data[4:]

        return self
