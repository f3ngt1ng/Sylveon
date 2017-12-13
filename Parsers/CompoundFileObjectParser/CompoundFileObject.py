# -*- coding: UTF-8 -*-


from Interfaces.IParseable import IParseable
from Interfaces.IVerifiable import IVerifiable
from Interfaces.PluginSupport import ISupportPlugin
from Parsers.CompoundFileObjectParser.CompoundFileHeader import CompoundFileHeader
from Parsers.CompoundFileObjectParser.CompoundFileObjectSector import CompoundFileObjectSector
from Parsers.CompoundFileObjectParser.Constants import END_OF_CHAIN, MAX_REGULAR_SECTOR, STREAM_OBJECT
from Parsers.CompoundFileObjectParser.DIFATSector import DIFATSector, DIFATSectorEntry
from Parsers.CompoundFileObjectParser.DirectorySector import DirectorySector
from Parsers.CompoundFileObjectParser.FATSector import FATSector
from Parsers.CompoundFileObjectParser.MiniFATSector import MiniFATSector
from Parsers.FileObjectParser.FileObject import FileObject
from ProjectExceptions import KnownError


class CompoundFileObject(FileObject, IParseable, IVerifiable, ISupportPlugin):
    def __init__(self, file_name = None):
        super().__init__(file_name = file_name)
        self.Header = CompoundFileHeader()

        self.DIFATEntries = []
        self.FATEntries = []
        self.MiniFATEntries = []
        self.DirectoryEntries = []

        self.Sectors = []
        self.MiniSectors = []

        self._sector_size = 0
        self._mini_sector_size = 0

        self.Streams = {}

        from Plugins.CompoundFileObjectPlugins.CVE_2017_11882 import CVE_2017_11882
        CompoundFileObject.enabled_plugins = [CVE_2017_11882]

        if file_name:
            self.parse(self.read())
            if not self.verify():
                raise KnownError("Invalid data.")

            self.Streams = self.extract_stream_data()

    def parse(self, data):
        # Parse the compound file header and initialize some variables.
        self.Header.parse(data)

        self._sector_size = 2 ** self.Header.SectorShift
        self._mini_sector_size = 2 ** self.Header.MiniSectorShift

        data = data[self._sector_size:]

        # Split the data into sectors.
        while len(data) > 0:
            self.Sectors.append(
                CompoundFileObjectSector().parse(data[:self._sector_size])
            )
            data = data[self._sector_size:]

        # Parse the DIFAT entries in the header.
        for index in range(109):
            self.DIFATEntries.append(DIFATSectorEntry().parse(self.Header.DIFAT[index * 4:index * 4 + 4]))

        # Parse the DIFAT entries in DIFAT sectors(if any).
        sector_count = 0
        current_parsing_sector_id = self.Header.FirstDIFATSectorLocation

        while current_parsing_sector_id != END_OF_CHAIN:
            sector_count += 1
            current_parsing_sector = DIFATSector().parse(self.Sectors[current_parsing_sector_id].Data)
            self.DIFATEntries += current_parsing_sector.DIFATSectorEntries
            current_parsing_sector_id = current_parsing_sector.NextSectorID
        if sector_count != self.Header.NumberOfDIFATSectors:
            raise KnownError("Wrong number of DIFAT sectors.")

        # Parse the FAT entries in FAT sectors.
        sector_count = 0

        for difat_entry in self.DIFATEntries:
            if difat_entry.SectorOffset >= MAX_REGULAR_SECTOR:
                continue

            sector_count += 1

            self.FATEntries += FATSector().parse(self.Sectors[difat_entry.SectorOffset].Data).FATSectorEntries
        if sector_count != self.Header.NumberOfFATSectors:
            raise KnownError("Wrong number of FAT sectors.")

        # Allocate sectors.
        while len(self.Sectors) < len(self.FATEntries):
            self.Sectors.append(
                CompoundFileObjectSector().parse(b"\x00" * self._sector_size)
            )

        # Chain the compound file sectors.
        for index, fat_entry in enumerate(self.FATEntries):
            current_parsing_sector = self.Sectors[index]
            current_parsing_sector.NextSectorID = fat_entry.NextSectorID

        # Check the sector chain again, make sure that all NextSectorIDs are valid.
        for sector in self.Sectors:
            if len(self.Sectors) <= sector.NextSectorID < MAX_REGULAR_SECTOR:
                sector.NextSectorID = END_OF_CHAIN

        # Parse the mini FAT entries in mini FAT sectors.
        sector_count = 0
        current_parsing_sector_id = self.Header.FirstMiniFATSectorLocation

        while current_parsing_sector_id != END_OF_CHAIN:
            sector_count += 1
            current_parsing_sector = MiniFATSector().parse(self.Sectors[current_parsing_sector_id].Data)
            self.MiniFATEntries += current_parsing_sector.MiniFATSectorEntries
            current_parsing_sector_id = self.Sectors[current_parsing_sector_id].NextSectorID

        if sector_count != self.Header.NumberOfMiniFATSectors:
            raise KnownError("Wrong number of mini FAT sectors.")

        # Parse the directory entries in directory sectors.
        sector_count = 0
        current_parsing_sector_id = self.Header.FirstDirectorySectorLocation

        while current_parsing_sector_id < MAX_REGULAR_SECTOR:
            sector_count += 1
            current_parsing_sector = DirectorySector().parse(self.Sectors[current_parsing_sector_id].Data)
            self.DirectoryEntries += current_parsing_sector.DirectorySectorEntries
            current_parsing_sector_id = self.Sectors[current_parsing_sector_id].NextSectorID

        if self.Header.MajorVersion == 0x4:
            if sector_count != self.Header.NumberOfDirectorySectors:
                raise KnownError("Wrong number of directory sectors.")

        # Allocate mini sectors.
        for _ in range(len(self.MiniFATEntries)):
            self.MiniSectors.append(CompoundFileObjectSector().parse(b"\x00" * self._mini_sector_size))

        # Chain the mini compound file sectors.
        root_storage_object = self.DirectoryEntries[0]

        mini_sector_data = self._read_data_from_sector_chain(
            sector_id = root_storage_object.StartingSectorLocation,
            sector_size = self._sector_size,
            data_length = self._mini_sector_size * len(self.MiniFATEntries)
        )

        for index in range(len(self.MiniFATEntries)):
            self.MiniSectors[index].parse(mini_sector_data[:self._mini_sector_size])
            mini_sector_data = mini_sector_data[self._mini_sector_size:]

        for index, mini_fat_entry in enumerate(self.MiniFATEntries):
            current_parsing_sector = self.MiniSectors[index]
            current_parsing_sector.NextSectorID = mini_fat_entry.NextSectorID

        # Check the mini sector chain again, make sure that all NextSectorIDs are valid.
        for mini_sector in self.MiniSectors:
            if len(self.MiniSectors) <= mini_sector.NextSectorID < MAX_REGULAR_SECTOR:
                mini_sector.NextSectorID = END_OF_CHAIN

        return self

    def verify(self):
        return self.Header.verify()

    def load_plugin(self, *args, **kwargs):
        self._load_plugin(stream_data = self.extract_stream_data())

    def extract_stream_data(self):
        stream_data = {}

        for directory_entry in self.DirectoryEntries:
            if directory_entry.ObjectType != STREAM_OBJECT:
                continue

            if directory_entry.StreamSize >= self.Header.MiniStreamCutoffSize:
                # Data is storaged in FAT stream.
                stream_data[directory_entry.DirectoryEntryName] = self._read_data_from_sector_chain(
                    sector_id = directory_entry.StartingSectorLocation,
                    sector_size = self._sector_size,
                    data_length = directory_entry.StreamSize
                )
            else:
                # Data is storaged in mini FAT stream.
                stream_data[directory_entry.DirectoryEntryName] = self._read_data_from_sector_chain(
                    sector_id = directory_entry.StartingSectorLocation,
                    sector_size = self._mini_sector_size,
                    data_length = directory_entry.StreamSize
                )

        return stream_data

    def _read_data_from_sector_chain(self, sector_id, sector_size, data_length):
        data = b""

        current_parsing_sector_id = sector_id
        current_parsing_sector_chain = None

        if sector_size == 64:
            current_parsing_sector_chain = self.MiniSectors
        if sector_size == 512 or sector_size == 4096:
            current_parsing_sector_chain = self.Sectors

        while data_length > 0:
            data_block_size = min(data_length, sector_size)

            current_parsing_sector = current_parsing_sector_chain[current_parsing_sector_id]
            data += current_parsing_sector.Data[:data_block_size]
            data_length -= data_block_size

            current_parsing_sector_id = current_parsing_sector.NextSectorID

            if current_parsing_sector_id >= MAX_REGULAR_SECTOR:
                break

        return data
