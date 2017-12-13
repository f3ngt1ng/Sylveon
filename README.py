# -*- coding: UTF-8 -*-


from Parsers.CompoundFileObjectParser.CompoundFileObject import CompoundFileObject
from ProjectExceptions import KnownError

try:
    file_object = CompoundFileObject("Documents\\CVE_2017_11882.doc")

    file_object.load_plugin()  # Loads all the plugins specified in CompoundFileObject.py

    # The "extract_stream" function will return a dict() object.


except KnownError:
    # Every exception caught in my program will be treated as "KnownError".
    # So I can just skip them easily.
    pass
