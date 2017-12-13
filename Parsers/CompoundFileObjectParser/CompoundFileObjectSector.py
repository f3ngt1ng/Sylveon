# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable


class CompoundFileObjectSector(IParseable):
    def __init__(self):
        self.Data = None
        self.NextSectorID = None

    def parse(self, data):
        self.Data = data

        return self
