# -*- coding: UTF-8 -*-


import logging.handlers

from ProjectConfiguration import ENABLE_CONSOLE_LOGGER, ENABLE_FILE_LOGGER, LOGGER_FILE_MODE, LOGGER_FILE_NAME, \
    LOGGER_FILE_SIZE, PROJECT_NAME


class ConsoleLogger(logging.StreamHandler):
    pass


class FileLogger(logging.handlers.RotatingFileHandler):
    pass


logger = logging.getLogger(PROJECT_NAME)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(fmt = "[%(asctime)s] [%(levelname)s] %(message)s",
                              datefmt = "%Y-%m-%d %H:%M:%S")

if ENABLE_CONSOLE_LOGGER:
    console_logger = ConsoleLogger()
    console_logger.setLevel(logging.INFO)  # info level
    console_logger.setFormatter(formatter)
    logger.addHandler(console_logger)

if ENABLE_FILE_LOGGER:
    file_logger = FileLogger(
        filename = LOGGER_FILE_NAME,
        mode = LOGGER_FILE_MODE,
        maxBytes = LOGGER_FILE_SIZE,
        backupCount = 5,
        encoding = "utf-8"
    )
    file_logger.setLevel(logging.DEBUG)  # debug level
    file_logger.setFormatter(formatter)
    logger.addHandler(file_logger)
