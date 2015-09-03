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
import os
import sys
import traceback
import argparse

OTX_KEY = "--- YOUR API KEY ---"

class OTXReceiver():

    # IOC Strings
    hash_iocs = ""
    filename_iocs = ""
    c2_iocs = ""

    def __init__(self, api_key, debug):
        self.debug = debug
        self.otx = OTXv2(api_key)

    def get_iocs_last(self):
        # mtime = (datetime.now() - timedelta(days=days_to_load)).isoformat()
        print "Starting OTX feed download ..."
        self.events = self.otx.getall()
        print "Download complete - %s events received" % len(self.events)
        json_normalize(self.events)

    def write_iocs(self, ioc_folder, separator, use_csv_header):

        hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.txt")
        filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.txt")
        c2_ioc_file = os.path.join(ioc_folder, "otx-c2-iocs.txt")

        print "Processing indicators ..."
        for event in self.events:
            try:
                for indicator in event["indicators"]:
                    if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):

                        self.hash_iocs += "{0}{3}{1} {2}\n".format(
                            indicator["indicator"],
                            event["name"].encode('unicode-escape'),
                            " / ".join(event["references"])[:80],
                            separator)

                    if indicator["type"] == 'FilePath':

                        self.filename_iocs += "{0}{3}{1} {2}\n".format(
                            my_escape(indicator["indicator"]),
                            event["name"].encode('unicode-escape'),
                            " / ".join(event["references"])[:80],
                            separator)

                    if indicator["type"] in ('domain', 'hostname', 'IPv4', 'IPv6', 'CIDR'):

                        self.c2_iocs += "{0}{3}{1} {2}\n".format(
                            indicator["indicator"],
                            event["name"].encode('unicode-escape'),
                            " / ".join(event["references"])[:80],
                            separator)

            except Exception, e:
                traceback.print_exc()

        # Write to files
        with open(hash_ioc_file, "w") as hash_fh:
            if use_csv_header:
                hash_fh.write('hash{0}description\n'.format(separator))
            hash_fh.write(self.hash_iocs)
            print "{0} hash iocs written to {1}".format(self.hash_iocs.count('\n'), hash_ioc_file)
        with open(filename_ioc_file, "w") as fn_fh:
            if use_csv_header:
                fn_fh.write('filename{0}description\n'.format(separator))
            fn_fh.write(self.filename_iocs)
            print "{0} filename iocs written to {1}".format(self.filename_iocs.count('\n'), filename_ioc_file)
        with open(c2_ioc_file, "w") as c2_fh:
            if use_csv_header:
                c2_fh.write('host{0}description\n'.format(separator))
            c2_fh.write(self.c2_iocs)
            print "{0} c2 iocs written to {1}".format(self.c2_iocs.count('\n'), c2_ioc_file)


def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\])',r'\\\1',string)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='OTX IOC Receiver')
    parser.add_argument('-k', help='OTX API key', metavar='APIKEY', default=OTX_KEY)
    # parser.add_argument('-l', help='Time frame in days (default=30)', default=30)
    parser.add_argument('-o', metavar='dir', help='Output directory', default='../iocs')
    parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
    parser.add_argument('--csvheader', action='store_true', default=False, help='Add column headers')
    parser.add_argument('-s', metavar='separator', default=';', help='Define separator')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 64:
        print "Set an API key in script or via -k APIKEY. Go to https://otx.alienvault.com create an account and get your own API key"
        sys.exit(0)

    # Create a receiver
    otx_receiver = OTXReceiver(api_key=args.k, debug=args.debug)

    # Retrieve the events and store the IOCs
    # otx_receiver.get_iocs_last(int(args.l))
    otx_receiver.get_iocs_last()

    # Write IOC files
    otx_receiver.write_iocs(ioc_folder=args.o, separator=args.s, use_csv_header=args.csvheader)