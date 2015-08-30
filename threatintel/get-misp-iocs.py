#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-MISP-IOCs
# Retrieves IOCs from MISP and stores them in appropriate format

MISP_KEY = '--- YOUR API KEY ---'
MISP_URL = 'https://misppriv.circl.lu'

import sys
import json
import argparse
import os
import re
from pymisp import PyMISP

class MISPReceiver():

    hash_iocs = {}
    filename_iocs = {}
    c2_iocs = {}

    debugon = False

    def __init__(self, misp_key, misp_url, misp_verify_cert, debugon=False):
        self.misp = PyMISP(misp_url, misp_key, misp_verify_cert, 'json')
        self.debugon = debugon

    def get_iocs_last(self, last):

        # Retrieve events from MISP
        result = self.misp.download_last(last)
        self.events = result['response']

        # Process each element (without related eevents)
        for event_element in self.events:
            event = event_element["Event"]

            # Info for Comment
            info = event['info']
            uuid = event['uuid']
            comment = "{0} - UUID: {1}".format(info.encode('unicode_escape'), uuid)

            # Event data
            for attribute in event['Attribute']:

                # Skip iocs that are not meant for ioc detection
                if attribute['to_ids'] == False:
                    continue

                # Value
                value = attribute['value']

                # Non split type
                if '|' not in attribute['type']:
                    self.add_ioc(attribute['type'], value, comment)
                # Split type
                else:
                    # Prepare values
                    type1, type2 = attribute['type'].split('|')
                    value1, value2 = value.split('|')
                    # self.add_ioc(type1, value1, comment)
                    self.add_ioc(type2, value2, comment)

    def add_ioc(self, ioc_type, value, comment):
        # Cleanup value
        value = value.encode('unicode_escape')
        # Debug
        if self.debugon:
            print "{0} = {1}".format(ioc_type, value)
        # C2s
        if ioc_type in ('hostname', 'ip-dst', 'domain'):
            self.c2_iocs[value] = comment
        # Hash
        if ioc_type in ('md5', 'sha1', 'sha256'):
            self.hash_iocs[value] = comment
        # Filenames
        if ioc_type in ('filename', 'filepath'):
            self.filename_iocs[my_escape(value)] = comment

    def write_iocs(self, output_path):
        # Write C2 IOCs
        self.write_file(os.path.join(output_path, "misp-c2-iocs.txt"), self.c2_iocs)
        # Write Filename IOCs
        self.write_file(os.path.join(output_path, "misp-filename-iocs.txt"), self.filename_iocs)
        # Write Hash IOCs
        self.write_file(os.path.join(output_path, "misp-hash-iocs.txt"), self.hash_iocs)

    def write_file(self, ioc_file, iocs):
        with open(ioc_file, "w") as file:
            for ioc in iocs:
                file.write("{0};{1}\n".format(ioc,iocs[ioc]))
        print "{0} IOCs written to file {1}".format(len(iocs), ioc_file)


def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\])',r'\\\1',string)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='MISP IOC Receiver')
    parser.add_argument('-u', help='MISP URL', metavar='URL', default=MISP_URL)
    parser.add_argument('-k', help='MISP API key', metavar='APIKEY', default=MISP_KEY)
    parser.add_argument('-l', help='Time frame (e.g. 2d, 12h - default=30d)', metavar='tframe', default='30d')
    parser.add_argument('-o', help='Output directory', metavar='dir', default='../iocs')
    parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 40:
        print "Set an API key in script or via -k APIKEY."
        sys.exit(0)

    # Create a receiver
    misp_receiver = MISPReceiver(misp_key=args.k, misp_url=args.u, misp_verify_cert=args.verifycert, debugon=args.debug)

    # Retrieve the events and store the IOCs
    misp_receiver.get_iocs_last(args.l)

    # Write IOC files
    misp_receiver.write_iocs(args.o)

