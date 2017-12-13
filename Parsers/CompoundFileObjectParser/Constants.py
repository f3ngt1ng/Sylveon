# -*- coding: UTF-8 -*-


# Color Flags
RED = 0x0
BLACK = 0x1

# Object Types
UNKNOWN_OR_UNALLOCATED = 0x0
STORAGE_OBJECT = 0x1
STREAM_OBJECT = 0x2
ROOT_STORAGE_OBJECT = 0x5

# Sector Types
MAX_REGULAR_SECTOR = 0xFFFFFFFA
NOT_APPLICABLE = 0xFFFFFFFB
DIFAT_SECTOR = 0xFFFFFFFC
FAT_SECTOR = 0xFFFFFFFD
END_OF_CHAIN = 0xFFFFFFFE
FREE_SECTOR = 0xFFFFFFFF

# Stream Types
MAX_REG_S_ID = 0xFFFFFFFA
NO_STREAM = 0xFFFFFFFF
