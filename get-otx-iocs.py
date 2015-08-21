#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-OTX-IOCs
# Retrieves IOCs from Open Threat Exchange

from OTXv2 import OTXv2
from pandas.io.json import json_normalize
from datetime import datetime, timedelta
import re

otx = OTXv2(" --- YOUR KEY HERE --- ")
hash_ioc_file = "./iocs/otx-hash-iocs.txt"
filename_ioc_file = "./iocs/otx-filename-iocs.txt"

mtime = (datetime.now() - timedelta(days=7)).isoformat()
events = otx.getevents_since(mtime)
events = otx.getall()
print len(events)
json_normalize(events)

# IOC Strings
hash_iocs = ""
filename_iocs = ""

for event in events:
    for indicator in event["indicators"]:
        if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):

            hash_iocs += "{0};{1} {2}\n".format(
                indicator["indicator"],
                event["name"].encode('unicode-escape'),
                " / ".join(event["references"])[:80])

        if indicator["type"] == 'FilePath':

            filename_iocs += "{0};{1} {2}\n".format(
                re.escape(indicator["indicator"]),
                event["name"].encode('unicode-escape'),
                " / ".join(event["references"])[:80])

# Write to files
with open(hash_ioc_file, "w") as hash_fh:
    hash_fh.write(hash_iocs)
with open(filename_ioc_file, "w") as fn_fh:
    fn_fh.write(filename_iocs)


