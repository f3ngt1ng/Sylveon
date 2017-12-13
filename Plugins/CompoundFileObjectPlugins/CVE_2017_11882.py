# -*- coding: UTF-8 -*-


import binascii
import string

from Interfaces.PluginSupport import IPlugin
from Tools.Logger import logger


class CVE_2017_11882(IPlugin):
    def __init__(self):
        self.name = "CVE-2017-11882"

    def verify(self, *args, **kwargs):
        return True

    def on_plugin_load(self, *args, **kwargs):
        stream_data = kwargs["stream_data"]

        for key in stream_data.keys():
            stream_name = str(key)
            if not stream_name.lower().startswith("equation native"):
                continue

            font_name = ""

            data = stream_data[key][28 + 5:]
            for i in range(len(data)):
                if data[i] != 0x08:  # font table record
                    continue
                else:
                    i += 3
                    while data[i] != 0x00:
                        font_name += chr(data[i])
                        i += 1
                    if len(font_name) > (4 - 1):  # does not contain \x00
                        font_name = font_name[:-(4 - 1)]  # strip the return address
                    break

            if len(font_name) + 1 > 36:
                logger.warning("CVE-2017-11882 exploit detected.")

                unprintable = len(list(filter(lambda x: x not in string.printable, font_name))) > 0

                logger.warning("Font name: \"{font_name}\". {maybe_shellcode}".format(
                    font_name = "".join(filter(lambda x: x in string.printable, font_name)),
                    maybe_shellcode = "It may be a piece of shellcode." if unprintable else ""
                ))

                if unprintable:  # maybe shellcode, so perform a hex dump.
                    logger.warning("Hex dump for font name:\n {hex_dump}".format(
                        hex_dump = binascii.hexlify(font_name.encode("ascii")).decode("ascii").upper()
                    ))

                suspicious_strings = []

                fragments = stream_data[key].split(b"\x00")
                fragments = list(filter(lambda x: len(x) > 0, fragments))

                index = 1
                for fragment in fragments:
                    suspicious_string = ""
                    for char in fragment:
                        if chr(char) in string.printable:
                            suspicious_string += chr(char)

                    if len(suspicious_string) > 5:  # or a lot of noises
                        suspicious_strings.append("({index}) {suspicious_string}".format(
                            index = index,
                            # did not strip the address after the command here
                            suspicious_string = suspicious_string.strip()
                        ))
                        index += 1

                logger.warning("Suspicious strings:\n" + "\n".join(suspicious_strings))

    def on_plugin_unload(self, *args, **kwargs):
        pass
