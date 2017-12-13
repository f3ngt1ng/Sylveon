# -*- coding: UTF-8 -*-


from Parsers.CompoundFileObjectParser.CompoundFileObject import CompoundFileObject
from ProjectExceptions import KnownError

from Tools.Logger import logger

try:
    file_object = CompoundFileObject("Documents\\CVE_2017_11882.doc")

    file_object.load_plugin()  # Loads all the plugins specified in CompoundFileObject.py

    # The "extract_stream" function will return a dict() object.
    streams = file_object.extract_stream_data()

    logger.info("Extracting streams from the document.")
    for key in streams.keys():
        logger.info("------------------------")
        logger.info("Stream name: {stream_name}".format(stream_name = str(key)))
        logger.info("Stream data: {stream_data}".format(stream_data = streams[key]))
        
except KnownError:
    # Every exception caught in my program will be treated as "KnownError".
    # So I can just skip them easily.
    pass
