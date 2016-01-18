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

HASH_BLACKLIST = [ 'e617348b8947f28e2a280dd93c75a6ad', '125da188e26bd119ce8cad7eeb1fc2dfa147ad47',
                   '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20' ]


class OTXReceiver():

    # IOC Strings
    hash_iocs = ""
    filename_iocs = ""
    c2_iocs = ""

    # Output format
    separator = ";"
    use_csv_header = False
    extension = "txt"
    hash_upper = False
    filename_regex_out = True

    def __init__(self, api_key, siem_mode, debug):
        self.debug = debug
        self.otx = OTXv2(api_key)
        if siem_mode:
            self.separator = ","
            self.use_csv_header = True
            self.extension = "csv"
            self.hash_upper = True
            self.filename_regex_out = False

    def get_iocs_last(self):
        # mtime = (datetime.now() - timedelta(days=days_to_load)).isoformat()
        print "Starting OTX feed download ..."
        self.events = self.otx.getall()
        print "Download complete - %s events received" % len(self.events)
        json_normalize(self.events)

    def write_iocs(self, ioc_folder):

        hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.{0}".format(self.extension))
        filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.{0}".format(self.extension))
        c2_ioc_file = os.path.join(ioc_folder, "otx-c2-iocs.{0}".format(self.extension))

        print "Processing indicators ..."
        for event in self.events:
            try:
                for indicator in event["indicators"]:
                    if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256') and \
                                    indicator["indicator"] not in HASH_BLACKLIST:

                        hash = indicator["indicator"]
                        if self.hash_upper:
                            hash = indicator["indicator"].upper()

                        self.hash_iocs += "{0}{3}{1} {2}\n".format(
                            hash,
                            event["name"].encode('unicode-escape'),
                            " / ".join(event["references"])[:80],
                            self.separator)

                    if indicator["type"] == 'FilePath':

                        filename = indicator["indicator"]
                        if self.filename_regex_out:
                            filename = my_escape(indicator["indicator"])

                        self.filename_iocs += "{0}{3}{1} {2}\n".format(
                            filename,
                            event["name"].encode('unicode-escape'),
                            " / ".join(event["references"])[:80],
                            self.separator)

                    if indicator["type"] in ('domain', 'hostname', 'IPv4', 'IPv6', 'CIDR'):

                        self.c2_iocs += "{0}{3}{1} {2}\n".format(
                            indicator["indicator"],
                            event["name"].encode('unicode-escape'),
                            " / ".join(event["references"])[:80],
                            self.separator)

            except Exception, e:
                traceback.print_exc()

        # Write to files
        with open(hash_ioc_file, "w") as hash_fh:
            if self.use_csv_header:
                hash_fh.write('hash{0}description\n'.format(self.separator))
            hash_fh.write(self.hash_iocs)
            print "{0} hash iocs written to {1}".format(self.hash_iocs.count('\n'), hash_ioc_file)
        with open(filename_ioc_file, "w") as fn_fh:
            if self.use_csv_header:
                fn_fh.write('filename{0}description\n'.format(self.separator))
            fn_fh.write(self.filename_iocs)
            print "{0} filename iocs written to {1}".format(self.filename_iocs.count('\n'), filename_ioc_file)
        with open(c2_ioc_file, "w") as c2_fh:
            if self.use_csv_header:
                c2_fh.write('host{0}description\n'.format(self.separator))
            c2_fh.write(self.c2_iocs)
            print "{0} c2 iocs written to {1}".format(self.c2_iocs.count('\n'), c2_ioc_file)


def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\\+])',r'\\\1',string)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='OTX IOC Receiver')
    parser.add_argument('-k', help='OTX API key', metavar='APIKEY', default=OTX_KEY)
    # parser.add_argument('-l', help='Time frame in days (default=30)', default=30)
    parser.add_argument('-o', metavar='dir', help='Output directory', default='../iocs')
    parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
    parser.add_argument('--siem', action='store_true', default=False, help='Add column headers')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 64:
        print "Set an API key in script or via -k APIKEY. Go to https://otx.alienvault.com create an account and get your own API key"
        sys.exit(0)

    # Create a receiver
    otx_receiver = OTXReceiver(api_key=args.k, siem_mode=args.siem, debug=args.debug)

    # Retrieve the events and store the IOCs
    # otx_receiver.get_iocs_last(int(args.l))
    otx_receiver.get_iocs_last()

    # Write IOC files
    otx_receiver.write_iocs(ioc_folder=args.o)