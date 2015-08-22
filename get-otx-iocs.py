#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-OTX-IOCs
# Retrieves IOCs from Open Threat Exchange
#
# Create an account and select your feeds
# https://otx.alienvault.com

from OTXv2 import OTXv2
from pandas.io.json import json_normalize
from datetime import datetime, timedelta
import re
import sys
import traceback

api_key = "--- YOUR OWN API KEY GOES HERE  ---"

if "API" in api_key:
    print "Go to https://otx.alienvault.com create an account and get your own API key"
    sys.exit(0)

otx = OTXv2(api_key)
hash_ioc_file = "./iocs/otx-hash-iocs.txt"
filename_ioc_file = "./iocs/otx-filename-iocs.txt"
c2_ioc_file = "./iocs/otx-c2-iocs.txt"

mtime = (datetime.now() - timedelta(days=7)).isoformat()

print "Starting OTX feed download ..."
events = otx.getall()
print "Download complete"

json_normalize(events)

# IOC Strings
hash_iocs = ""
filename_iocs = ""
c2_iocs = ""

print "Processing indicators ..."
for event in events:
    try:
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

            if indicator["type"] in ('domain', 'hostname', 'IPv4', 'IPv6', 'CIDR'):

                c2_iocs += "{0};{1} {2}\n".format(
                    indicator["indicator"],
                    event["name"].encode('unicode-escape'),
                    " / ".join(event["references"])[:80])

    except Exception, e:
        traceback.print_exc()

# Write to files
with open(hash_ioc_file, "w") as hash_fh:
    hash_fh.write(hash_iocs)
    print "{0} hash iocs written to {1}".format(hash_iocs.count('\n'), hash_ioc_file)
with open(filename_ioc_file, "w") as fn_fh:
    fn_fh.write(filename_iocs)
    print "{0} filename iocs written to {1}".format(filename_iocs.count('\n'), filename_ioc_file)
with open(c2_ioc_file, "w") as c2_fh:
    c2_fh.write(c2_iocs)
    print "{0} c2 iocs written to {1}".format(c2_iocs.count('\n'), c2_ioc_file)

