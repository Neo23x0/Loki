#!/usr/bin/env python2.7
"""Checks Hashes read from an input file on Virustotal""" 

__AUTHOR__ = 'Florian Roth'
__VERSION__ = "0.3 July 2016"

"""
Install dependencies with:
pip install simplejson bs4 colorama pickle
"""

import simplejson
import urllib
import urllib2
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
VENDORS = ['Microsoft', 'Kaspersky', 'McAfee']
API_KEY = ''
WAIT_TIME = 15 # Public API allows 4 request per minute, so we wait 15 secs by default 


def fetch_hash(line):
    pattern = r'\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'
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
    colorer = re.compile('([A-Z_]{2,}:)\s', re.VERBOSE)
    line = colorer.sub(Fore.BLACK+hl_color+r'\1'+Style.RESET_ALL+' ', line)
    print line


def process_permalink(url, debug=False):
    """
    Requests the HTML page for the sample and extracts other useful data 
    that is not included in the public API 
    """
    headers = {'User-Agent' : 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
               'Referrer': 'https://www.virustotal.com/en/' }
    request = urllib2.Request(url, None, headers)
    info = {'filenames': ['-'], 'firstsubmission': '-'}
    try:
        response = urllib2.urlopen(request)
        source_code = response.read()
        # Extract info from source code
        soup = BeautifulSoup(source_code, 'html.parser')
        # Get file names
        elements = soup.find_all('td')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text == "File names":
                file_names = elements[i+1].text.strip().split("\n")
                info['filenames'] = filter(None, map(lambda file: file.strip(), file_names))
        # Get first submission
        elements = soup.findAll("div", { "class" : "enum" })
        for i, row in enumerate(elements):
            text = row.text.strip()
            if 'First submission' in text:
                first_submission_raw = elements[i].text.strip().split("\n")
                info['firstsubmission'] = first_submission_raw[1].strip()
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


def signal_handler(signal, frame):
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)
    sys.exit(0)


def process_lines(lines, result_file, nocsv=False, dups=False, debug=False):
    """
    Process the input file line by line
    """

    for line in lines:

        # Skip comments
        if line.startswith("#"):
            continue
        
        # Remove line break
        line.rstrip("\n\r\l")

        # Get all hashes in line 
        # ... and the rest of the line as comment
        hash, comment = fetch_hash(line)

        # If no hash found
        if hash == '':
            continue

        # Cache
        if hash in cache:
            if dups:
                # Colorized head of each hash check 
                print_highlighted("\nHASH: {0} COMMENT: {1}".format(hash, comment))
                print_highlighted("RESULT: %s (from cache)" % cache[hash])
            continue
        else:
            # Colorized head of each hash check 
            print_highlighted("\nHASH: {0} COMMENT: {1}".format(hash, comment))

        # Prepare VT API request
        parameters = {"resource": hash, "apikey": API_KEY}
        success = False
        while not success:
            try:
                data = urllib.urlencode(parameters)
                req = urllib2.Request(URL, data)
                response = urllib2.urlopen(req)
                json = response.read()
                response_dict = simplejson.loads(json)
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
        rating = "unknown"
        positives = 0
        res_color = Back.CYAN
        # print simplejson.dumps(response_dict, sort_keys=True, indent=4)
        if response_dict.get("response_code") > 0:
            # AV matches
            positives = response_dict.get("positives")
            total = response_dict.get("total")
            last_submitted = response_dict.get("scan_date")
            # Virus Name 
            scans = response_dict.get("scans")
            virus_names = []
            for vendor in VENDORS:
                if vendor in scans:
                    if scans[vendor]["result"]:
                        virus_names.append(scans[vendor]["result"])
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
            filenames = ", ".join(info['filenames'][:5]).replace(';', '_')
            first_submitted = info['firstsubmission']
            # Result 
            result = "%s / %s" % ( response_dict.get("positives"), response_dict.get("total") )
            print_highlighted("VIRUS: {0}".format(virus))
            print_highlighted("FILENAMES: {0}".format(filenames))
            print_highlighted("FIRST_SUBMITTED: {0} LAST_SUBMITTED: {1}".format(first_submitted, last_submitted))
        
        # Print the highlighted result line
        print_highlighted("RESULT: %s" % result, hl_color=res_color)

        # Add to log file
        if not nocsv:
            result_line = "{0};{1};{2};{3};{4};{5};{6};{7}\n".format(hash, rating, comment, positives, virus, filenames, first_submitted, last_submitted)
            with open(result_file, "a") as fh_results:
                fh_results.write(result_line)

        # Add to hash cache
        cache[hash] = result

        # Wait some time for the next request
        time.sleep(WAIT_TIME)

if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)
    init(autoreset=False)

    print Style.RESET_ALL
    print Fore.BLACK + Back.WHITE
    print " ".ljust(80)
    print " Virustotal Online Checker".ljust(80)
    print (" " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80)
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
        print "[+] You can always interrupt the scan by pressing CTRL+C without loosing the scan state"
    
    # Open input file
    try:
        with open(args.f, 'r') as fh:
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
                    fh_results.write("Hash;Rating;Comment;Positives;Virus;File Names;First Submitted;Last Submitted\n")
            except Exception, e:
                print "[E] Cannot write export file {0}".format(result_file)

    # Process the input lines
    process_lines(lines, result_file, args.nocsv, args.dups, args.debug)

    # Write Cache
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)

    print Style.RESET_ALL
