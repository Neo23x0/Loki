#!/usr/bin/env python2.7
"""Checks Hashes read from an input file on Virustotal"""

__AUTHOR__ = 'Florian Roth'
__VERSION__ = "0.10 September 2017"

"""
Modified by Hannah Ward: clean up, removal of simplejson, urllib2 with requests

Install dependencies with:
pip install requests bs4 colorama
"""

import requests
import time
import re
import os
import signal
import sys
import pickle
from bs4 import BeautifulSoup
import traceback
import argparse
from colorama import init, Fore, Back, Style

URL = r'https://www.virustotal.com/vtapi/v2/file/report'
VENDORS = ['Microsoft', 'Kaspersky', 'McAfee', 'CrowdStrike', 'TrendMicro',
           'ESET-NOD32', 'Symantec', 'F-Secure', 'Sophos', 'GData']
API_KEY = '-'
WAIT_TIME = 15  # Public API allows 4 request per minute, so we wait 15 secs by default


def fetch_hash(line):
    pattern = r'(?<!FIRSTBYTES:\s)\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'
    hash_search = re.findall(pattern, line)
    if len(hash_search) > 0:
        hash = hash_search[-1]
        rest = ' '.join(re.sub('({0}|;|,|:)'.format(hash), ' ', line).strip().split())

        return hash, rest
    return '', ''


def print_highlighted(line, hl_color=Back.WHITE):
    """
    Print a highlighted line
    """
    # Tags
    colorer = re.compile('(HARMLESS|SIGNED|MS_SOFTWARE_CATALOGUE)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.GREEN + r'\1' + Style.RESET_ALL + ' ', line)
    colorer = re.compile('(SIG_REVOKED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.RED + r'\1' + Style.RESET_ALL + ' ', line)
    colorer = re.compile('(SIG_EXPIRED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.YELLOW + r'\1' + Style.RESET_ALL + ' ', line)
    # Extras
    colorer = re.compile('(\[!\])', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.CYAN + r'\1' + Style.RESET_ALL + ' ', line)
    # Standard
    colorer = re.compile('([A-Z_]{2,}:)\s', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + hl_color + r'\1' + Style.RESET_ALL + ' ', line)
    print line


def process_permalink(url, debug=False):
    """
    Requests the HTML page for the sample and extracts other useful data
    that is not included in the public API
    """
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
               'Referrer': 'https://www.virustotal.com/en/'}
    info = {'filenames': ['-'], 'firstsubmission': '-', 'harmless': False, 'signed': False, 'revoked': False,
            'expired': False, 'mssoft': False, 'imphash': '-', 'filetype': '-'}
    try:
        source_code = requests.get(url, headers=headers)
        # Extract info from source code
        soup = BeautifulSoup(source_code.text, 'html.parser')
        # Get file names
        elements = soup.find_all('td')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text == "File names":
                file_names = elements[i + 1].text.strip().split("\n")
                info['filenames'] = filter(None, map(lambda file: file.strip(), file_names))
        # Get file names
        elements = soup.find_all('div')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text.startswith('File type'):
                info['filetype'] = elements[i].text[10:].strip()
        # Get additional information
        elements = soup.findAll("div", {"class": "enum"})
        for i, row in enumerate(elements):
            text = row.text.strip()
            if 'First submission' in text:
                first_submission_raw = elements[i].text.strip().split("\n")
                info['firstsubmission'] = first_submission_raw[1].strip()
            if 'imphash' in text:
                info['imphash'] = elements[i].text.strip().split("\n")[-1].strip()
        # Harmless
        if "Probably harmless!" in source_code:
            info['harmless'] = True
        # Signed
        if "Signed file, verified signature" in source_code:
            info['signed'] = True
        # Revoked
        if "revoked by its issuer" in source_code:
            info['revoked'] = True
        # Expired
        if "Expired certificate" in source_code:
            info['expired'] = True
        # Microsoft Software
        if "This file belongs to the Microsoft Corporation software catalogue." in source_code:
            info['mssoft'] = True
    except Exception, e:
        if debug:
            traceback.print_exc()
    finally:
        # Return the info dictionary
        return info


def saveCache(cache, fileName):
    """
    Saves the cache database as pickle dump to a file
    :param cache:
    :param fileName:
    :return:
    """
    with open(fileName, 'wb') as fh:
        pickle.dump(cache, fh, pickle.HIGHEST_PROTOCOL)


def loadCache(fileName):
    """
    Load cache database as pickle dump from file
    :param fileName:
    :return:
    """
    try:
        with open(fileName, 'rb') as fh:
            return pickle.load(fh), True
    except Exception, e:
        # traceback.print_exc()
        return {}, False


def removeNonAsciiDrop(string):
    nonascii = "error"
    # print "CON: ", string
    try:
        # Generate a new string without disturbing characters and allow new lines
        nonascii = "".join(i for i in string if (ord(i) < 127 and ord(i) > 31) or ord(i) == 10 or ord(i) == 13)
    except Exception, e:
        traceback.print_exc()
        pass
    return nonascii


def signal_handler(signal, frame):
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)
    sys.exit(0)


def process_lines(lines, result_file, nocsv=False, dups=False, debug=False):
    """
    Process the input file line by line
    """

    # Some statistics that could help find similarities
    imphashes = {}

    for line in lines:

        # Skip comments
        if line.startswith("#"):
            continue

        # Remove line break
        line.rstrip("\n\r")

        # Get all hashes in line
        # ... and the rest of the line as comment
        hashVal, comment = fetch_hash(line)

        # If no hash found
        if hashVal == '':
            continue

        # Cache
        if hashVal in cache:
            if dups:
                # Colorized head of each hash check
                print_highlighted("\nHASH: {0} COMMENT: {1}".format(hashVal, comment))
                print_highlighted("RESULT: %s (from cache)" % cache[hashVal])
            continue
        else:
            # Colorized head of each hash check
            print_highlighted("\nHASH: {0} COMMENT: {1}".format(hashVal, comment))

        # Prepare VT API request
        parameters = {"resource": hashVal, "apikey": API_KEY}
        success = False
        while not success:
            try:
                response_dict = requests.get(URL, params=parameters).json()
                success = True
            except Exception, e:
                if debug:
                    traceback.print_exc()
                    # print "Error requesting VT results"
                pass

        # Process results
        result = "- / -"
        virus = "-"
        last_submitted = "-"
        first_submitted = "-"
        filenames = "-"
        filetype = "-"
        rating = "unknown"
        positives = 0
        res_color = Back.CYAN
        md5 = "-"
        sha1 = "-"
        sha256 = "-"
        imphash = "-"
        harmless = ""
        signed = ""
        revoked = ""
        expired = ""
        mssoft = ""
        vendor_result_string = "-"

        if response_dict.get("response_code") > 0:
            # Hashes
            md5 = response_dict.get("md5")
            sha1 = response_dict.get("sha1")
            sha256 = response_dict.get("sha256")
            # AV matches
            positives = response_dict.get("positives")
            total = response_dict.get("total")
            last_submitted = response_dict.get("scan_date")
            # Virus Name
            scans = response_dict.get("scans")
            virus_names = []
            vendor_results = []
            for vendor in VENDORS:
                if vendor in scans:
                    if scans[vendor]["result"]:
                        virus_names.append("{0}: {1}".format(vendor, scans[vendor]["result"]))
                        vendor_results.append(scans[vendor]["result"])
                    else:
                        vendor_results.append("-")
                else:
                    vendor_results.append("-")
            vendor_result_string = ";".join(vendor_results)
            if len(virus_names) > 0:
                virus = " / ".join(virus_names)
            # Type
            rating = "clean"
            res_color = Back.GREEN
            if positives > 0:
                rating = "suspicious"
                res_color = Back.YELLOW
            if positives > 10:
                rating = "malicious"
                res_color = Back.RED
            # Get more information with permalink
            if debug:
                print "[D] Processing permalink {0}".format(response_dict.get("permalink"))
            info = process_permalink(response_dict.get("permalink"), debug)
            # File Names
            filenames = removeNonAsciiDrop(", ".join(info['filenames'][:5]).replace(';', '_'))
            first_submitted = info['firstsubmission']
            # Other info
            filetype = info['filetype']
            imphash = info['imphash']
            if imphash != "-":
                if imphash in imphashes:
                    print_highlighted("[!] Imphash seen in %d samples "
                                      "https://totalhash.cymru.com/search/?hash:%s" %
                                      (imphashes[imphash], imphash), hl_color=res_color)
                    imphashes[imphash] += 1
                else:
                    imphashes[imphash] = 1
            # Result
            result = "%s / %s" % (response_dict.get("positives"), response_dict.get("total"))
            print_highlighted("VIRUS: {0}".format(virus))
            print_highlighted("FILENAMES: {0}".format(filenames))
            print_highlighted("FILE_TYPE: {2} FIRST_SUBMITTED: {0} LAST_SUBMITTED: {1}".format(
                first_submitted, last_submitted, filetype))

            # Permalink analysis results
            if info['harmless']:
                harmless = " HARMLESS"
            if info['signed']:
                signed = " SIGNED"
            if info['revoked']:
                revoked = " SIG_REVOKED"
            if info['expired']:
                expired = " SIG_EXPIRED"
            if info["mssoft"]:
                mssoft = "MS_SOFTWARE_CATALOGUE"

        # Print the highlighted result line
        print_highlighted("RESULT: %s %s%s%s%s%s" % (result, harmless, signed, revoked, expired, mssoft),
                          hl_color=res_color)

        # Add to log file
        if not nocsv:
            result_line = "{0};{1};{2};{3};{4};{5};{6};{7};" \
                          "{8};{9};{10};{11};{12};{13};{14};{15};{16};{17}\n".format(hashVal, rating, comment,
                                                                                     positives,
                                                                                     virus, filenames,
                                                                                     first_submitted,
                                                                                     last_submitted,
                                                                                     filetype,
                                                                                     md5, sha1, sha256, imphash,
                                                                                     harmless.lstrip(' '),
                                                                                     signed.lstrip(' '),
                                                                                     revoked.lstrip(' '),
                                                                                     expired.lstrip(' '),
                                                                                     vendor_result_string)
            with open(result_file, "a") as fh_results:
                fh_results.write(result_line)

        # Add to hash cache
        cache[hashVal] = result

        # Wait some time for the next request
        time.sleep(WAIT_TIME)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)
    init(autoreset=False)

    print Style.RESET_ALL
    print Fore.WHITE + Back.BLUE
    print " ".ljust(80)
    print "   _   ________  _______           __           ".ljust(80)
    print "  | | / /_  __/ / ___/ /  ___ ____/ /_____ ____ ".ljust(80)
    print "  | |/ / / /   / /__/ _ \/ -_) __/  '_/ -_) __/ ".ljust(80)
    print "  |___/ /_/    \___/_//_/\\__/\__/_/\_\\__/_/    ".ljust(80)
    print "                                               ".ljust(80)
    print ("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80)
    print " ".ljust(80) + Style.RESET_ALL
    print Style.RESET_ALL + " "

    parser = argparse.ArgumentParser(description='Virustotal Online Checker')
    parser.add_argument('-f', help='File to process (hash line by line OR csv with hash in each line - auto-detects '
                                   'position and comment)', metavar='path', default='')
    parser.add_argument('-c', help='Name of the cache database file (default: vt-hash-db.pkl)', metavar='cache-db',
                        default='vt-hash-db.pkl')
    parser.add_argument('--nocache', action='store_true', help='Do not use cache database file', default=False)
    parser.add_argument('--nocsv', action='store_true', help='Do not write a CSV with the results', default=False)
    parser.add_argument('--dups', action='store_true', help='Do not skip duplicate hashes', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Check API Key
    if API_KEY == '':
        print "[E] No API Key set"
        print "    Include your API key in the header section of the script (API_KEY)\n"
        print "    More info:"
        print "    https://www.virustotal.com/en/faq/#virustotal-api\n"
        sys.exit(1)

    # Check input file
    if args.f == '':
        print "[E] Please provide an input file with '-f inputfile'\n"
        parser.print_help()
        sys.exit(1)
    if not os.path.exists(args.f):
        print "[E] Cannot find input file {0}".format(args.f)
        sys.exit(1)

    # Caches
    cache = {}
    # Trying to load cache from pickle dump
    if not args.nocache:
        cache, success = loadCache(args.c)
        if success:
            print "[+] {0} cache entries read from cache database: {1}".format(len(cache), args.c)
        else:
            print "[-] No cache database found"
            print "[+] Analyzed hashes will be written to cache database: {0}".format(args.c)
        print "[+] You can always interrupt the scan by pressing CTRL+C without losing the scan state"

    # Open input file
    try:
        with open(args.f, 'rU') as fh:
            lines = fh.readlines()
    except Exception, e:
        print "[E] Cannot read input file "
        sys.exit(1)

    # Result file
    # Result file
    if not args.nocsv:
        result_file = "check-results_{0}.csv".format(os.path.splitext(os.path.basename(args.f))[0])
        if os.path.exists(result_file):
            print "[+] Found results CSV from previous run: {0}".format(result_file)
            print "[+] Appending results to file: {0}".format(result_file)
        else:
            print "[+] Writing results to new file: {0}".format(result_file)
            try:
                with open(result_file, 'w') as fh_results:
                    fh_results.write("Lookup Hash;Rating;Comment;Positives;Virus;File Names;First Submitted;"
                                     "Last Submitted;MD5;SHA1;SHA256;ImpHash;Harmless;Signed;Revoked;Expired;"
                                     "{0}\n".format(";".join(VENDORS)))
            except Exception, e:
                print "[E] Cannot write export file {0}".format(result_file)

    # Process the input lines
    process_lines(lines, result_file, args.nocsv, args.dups, args.debug)

    # Write Cache
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)

    print Style.RESET_ALL

