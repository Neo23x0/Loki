#!/usr/bin/env python2.7
"""Checks IPs and Hosts read from an input file on Virustotal"""

__AUTHOR__ = 'Florian Roth'
__VERSION__ = "0.2 July 2017"

"""
Install dependencies with:
pip install simplejson colorama IPy pickle pycurl
"""

import simplejson, json
import signal
import urllib
import urllib2
import pycurl
import StringIO
import urlparse
import platform
import time
import re
import os
import sys
import traceback
import subprocess
import argparse
import socket
import pickle
from IPy import IP
from colorama import init, Fore, Back, Style

URLS = {'ip': r'https://www.virustotal.com/vtapi/v2/ip-address/report',
        'domain': r'https://www.virustotal.com/vtapi/v2/domain/report'}
API_KEY = '-'
WAIT_TIME = 15  # Public API allows 4 request per minute, so we wait 15 secs by default
IP_WHITE_LIST = ['1.0.0.127', '127.0.0.1']
OWNER_WHITE_LIST = ['Google Inc.', 'Facebook, Inc.', 'CloudFlare, Inc.', 'Microsoft Corporation',
                    'Akamai Technologies, Inc.']  # not yet used
DOMAIN_WHITE_LIST = ['sourceforge.net']
RES_TARGETS = {'ip': 'hostname', 'domain': 'ip_address'}


def fetch_ip_and_domains(line):
    """
    Extracts IPs and Domains from a log line
    """
    domains = []
    # Modify line to easily extract IPs and Domains from reports
    # get 183.200.23[.]213
    mod_line = line.replace("[", "").replace("]", "")
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = re.findall(ip_pattern, mod_line)
    domain_pattern = r'\b(?=.{4,253}$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z0-9-]{3,40}\.[a-zA-Z]{2,63})\b'
    domains_raw = re.findall(domain_pattern, mod_line)
    for domain in domains_raw:
        domains.append(domain[0])
    return ips, domains


def is_ip(value):
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'
    if re.match(ip_pattern, value):
        return True
    return False


def is_private(ip):
    ip = IP(ip)
    if ip.iptype() == "PRIVATE":
        return True
    return False


def is_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception, e:
        # traceback.print_exc()
        return False


def is_pingable(ip):
    """
    Ping the target IP
    :param ip:
    :return:
    """
    try:
        # Ping parameters as function of OS
        ping_str = "-n 1 -w 500" if platform.system().lower() == "windows" else "-c 1 -W 500"
        # Ping
        subprocess.check_output("ping {0} {1}".format(ping_str, ip),
                                stderr=subprocess.STDOUT,
                                shell=True)
        return True
    except Exception, e:
        # traceback.print_exc()
        return False


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


def print_highlighted(line, hl_color=Back.WHITE):
    """
    Print a highlighted line
    """
    try:
        # Highlight positives
        colorer = re.compile(r'([^\s]+) POSITIVES: ([1-9]) ')
        line = colorer.sub(Fore.YELLOW + r'\1 ' + 'POSITIVES: ' + Fore.YELLOW + r'\2 ' + Style.RESET_ALL, line)
        colorer = re.compile(r'([^\s]+) POSITIVES: ([0-9]+) ')
        line = colorer.sub(Fore.RED + r'\1 ' + 'POSITIVES: ' + Fore.RED + r'\2 ' + Style.RESET_ALL, line)
        # Keyword highlight
        colorer = re.compile(r'([A-Z_]{2,}:)\s', re.VERBOSE)
        line = colorer.sub(Fore.BLACK + hl_color + r'\1' + Style.RESET_ALL + ' ', line)
        print line
    except Exception, e:
        pass


def process_lines(lines, debug=False):
    """
    Process the input file line by line
    """
    # Counter
    linenr = 0
    # Elements
    elements = []

    # Loop through lines -----------------------------------------------------------------------------------------------
    for line in lines:
        # Skip comments
        if line.startswith("#"):
            continue

        ips, domains = fetch_ip_and_domains(line)
        if debug:
            if len(ips):
                print "[D] IPs: {0}".format(', '.join(ips))
            if len(domains):
                print "[D] Domains: {0}".format(', '.join(domains))

        # Line number
        linenr += 1

        # If no IP or Domain found in line
        if len(ips) < 1 and len(domains) < 1:
            continue

        # Elements
        for i in ips:
            elements.append({"value": i, "type": "ip"})
        for h in domains:
            elements.append({"value": h, "type": "domain"})

    return elements


def process_elements(elements, result_file, max_items, nocsv=False, dups=False, noresolve=False, ping=False,
                     debug=False):
    # Counter
    i = 0

    while i < len(elements):

        # Get the current element
        element = elements[i]
        value = element["value"]
        cat = element["type"]

        # Count
        i += 1

        # Cache ------------------------------------------------------------------------------------------------
        if value in cache:
            if dups:
                # Colorized head of each hash check
                print_highlighted("\n{0}: {1}".format(str.upper(cat), value), Back.CYAN)
                print_highlighted("RESULT: %s (from cache)" % cache[value])
            continue

        # Skips ------------------------------------------------------------------------------------------------
        # Is private
        if cat == 'ip':
            # Skip private IPs
            if is_private(value):
                if debug:
                    # Add to cache
                    cache[value] = 'skipped'
                    print "[D] IP {0} is a private IP - skipping".format(value)
                continue
            # Skip unreachable systems
            if ping:
                if not is_pingable(value):
                    # Add to cache
                    cache[value] = 'skipped'
                    if debug:
                        print "[D] IP {0} ping failed - skipping".format(value)
                    continue

        # White lists
        for dom in DOMAIN_WHITE_LIST:
            if dom in value:
                print_highlighted("Domain white-listed - skipping this host SYSTEM: %s" % value)
                cache[value] = 'skipped'

        for iwl in IP_WHITE_LIST:
            if iwl == value:
                print_highlighted("IP white-listed - skipping this host SYSTEM: %s" % value)
                cache[value] = 'skipped'

        if value in cache:
            if cache[value] == 'skipped':
                continue

        # Is resolvable
        if not noresolve:
            if cat == 'domain':
                if not is_resolvable(value):
                    # Add to cache
                    cache[value] = 'skipped'
                    continue

        # Head -------------------------------------------------------------------------------------------------
        # Colorized head of each hash check
        print_highlighted("\n{0}: {1}".format(str.upper(cat), value), Back.CYAN)

        # VT API Request ---------------------------------------------------------------------------------------
        # Prepare VT API request
        parameters = {cat: value, "apikey": API_KEY}
        success = False

        while not success:
            try:
                parameters = {cat: value, 'apikey': API_KEY}
                if debug:
                    print "URL: %s" % URLS[cat]
                    print "PARAMS: %s" % parameters

                response = urllib.urlopen('%s?%s' % (URLS[cat], urllib.urlencode(parameters))).read()
                response_dict = simplejson.loads(response)
                success = True
            except Exception, e:
                if debug:
                    traceback.print_exc()
                    # print "Error requesting VT results"
                pass
        if debug:
            print json.dumps(response_dict, indent=4, sort_keys=True)

        # Process results --------------------------------------------------------------------------------------
        result = "- / -"
        rating = "unknown"
        owner = "-"
        country = "-"
        positives = 0
        total = 0
        sample_positives = 0
        sample_total = 0
        resolutions = []
        urls = []
        samples = []
        res_color = Back.CYAN
        shown_messages = {}

        # print simplejson.dumps(response_dict, sort_keys=True, indent=4)
        if response_dict.get("response_code") > 0:

            # Predefine Rating
            rating = "clean"

            # Other Info
            owner = response_dict.get("as_owner")
            country = response_dict.get("country")

            # WHITE LIST CHECKS
            if owner:
                for owl in OWNER_WHITE_LIST:
                    if owl in owner:
                        print_highlighted("Owner white-listed - skipping this host OWNER: %s" % owner)

            # Resolutions
            if 'resolutions' in response_dict:
                resolution_list = response_dict['resolutions']
                for i, res in enumerate(resolution_list):
                    resolutions.append({'target': res[RES_TARGETS[cat]], 'last_resolved': res['last_resolved']})
                    if i < max_items:
                        print_highlighted("HOST: {0} LAST_RESOLVED: {1}".format(res[RES_TARGETS[cat]],
                                                                                res['last_resolved']))
                    else:
                        if "hosts" not in shown_messages:
                            sys.stdout.write("Others found: ")
                            shown_messages["hosts"] = True
                        sys.stdout.write(".")
                    # Add the IP to the elements
                    if args.recursive:
                        new_value = res[RES_TARGETS[cat]]
                        if is_ip(new_value):
                            elements.append({'value': new_value, 'type': 'ip'})
                        else:
                            elements.append({'value': new_value, 'type': 'domain'})
                if "hosts" in shown_messages:
                    sys.stdout.write("\n")

            # URL matches
            if 'detected_urls' in response_dict:
                detected_urls = response_dict['detected_urls']
                for i, url in enumerate(detected_urls):
                    positives_url = url['positives']
                    total_url = url['total']
                    urls.append({'url': url['url'], 'positives': positives_url, 'total': total_url})
                    if i < max_items and args.download:
                        print_highlighted("URL: {0} POSITIVES: {1} TOTAL: {2}".format(url['url'],
                                                                                      positives_url,
                                                                                      total_url))
                    else:
                        if "urls" not in shown_messages:
                            sys.stdout.write("Others found: ")
                            shown_messages["urls"] = True
                        sys.stdout.write(".")
                    positives += positives_url
                    total += total_url
                    # Download URL
                    if args.download:
                        download_url(value, url['url'])
                if "urls" in shown_messages:
                    sys.stdout.write("\n")

            # Samples
            if 'detected_communicating_samples' in response_dict:
                samples_list = response_dict['detected_communicating_samples']
                for i, sample in enumerate(samples_list):
                    positives_sample = sample['positives']
                    total_sample = sample['total']
                    date = sample['date']
                    sha256 = sample['sha256']
                    samples.append({'sample': sha256, 'positives': positives_sample, 'total': total_sample,
                                    'date': date})
                    if i < max_items:
                        print_highlighted("SAMPLE: {0} POSITIVES: {1} TOTAL: {2} "
                                          "DATE: {3}".format(sha256, positives_sample, total_sample, date))
                    else:
                        if "samples" not in shown_messages:
                            sys.stdout.write("Others found: ")
                            shown_messages["samples"] = True
                        sys.stdout.write(".")
                    sample_positives += positives_sample
                    sample_total += total_sample
                if "samples" in shown_messages:
                    sys.stdout.write("\n")

            # Calculations -------------------------------------------------------------------------------------
            # Rating
            # Calculate ratio
            if positives > 0 and total > 0:
                ratio = (float(positives) / float(total)) * 100
                # Set rating
                if ratio > 3 and rating == "clean":
                    rating = "suspicious"
                if ratio > 10 and (rating == "clean" or rating == "suspicious"):
                    rating = "malicious"

            # Type
            res_color = Back.GREEN
            if rating == "suspicious":
                res_color = Back.YELLOW
            if rating == "malicious":
                res_color = Back.RED

            # Result -------------------------------------------------------------------------------------------
            result = "%s / %s" % (positives, total)
            print_highlighted("COUNTRY: {0} OWNER: {1}".format(country, owner))
            print_highlighted("POSITIVES: %s RATING: %s" % (result, rating), hl_color=res_color)

        else:
            # Print the highlighted result line
            print_highlighted("POSITIVES: %s RATING: %s" % (result, rating), hl_color=res_color)

        # CSV OUTPUT -------------------------------------------------------------------------------------------
        # Add to log file
        if not nocsv:
            # Hosts string
            targets = []
            for r in resolutions:
                targets.append(r['target'])
            targets_value = ', '.join(targets)
            # Malicious samples
            mal_samples = []
            for s in samples:
                if s['positives'] > 3:
                    mal_samples.append(s['sample'])
            samples_value = ', '.join(mal_samples)
            # urls = ', '.join("%s=%r" % (key,val) for (key,val) in urls.iteritems())
            # samples = ', '.join("%s=%r" % (key,val) for (key,val) in samples.iteritems())
            result_line = "{0};{1};{2};{3};{4};{5};{6};{7}\n".format(value, rating, owner, country,
                                                                     positives, total,
                                                                     samples_value, targets_value)
            with open(result_file, "a") as fh_results:
                fh_results.write(result_line)

        # Add to cache -----------------------------------------------------------------------------------------
        cache[value] = result

        # Wait -------------------------------------------------------------------------------------------------
        # Wait some time for the next request
        time.sleep(WAIT_TIME)


def download_url(host_id, url):
    """
    Downloads an URL and stores the response to a directory with named as the host/IP
    :param host_id:
    :param url:
    :return:
    """
    output = StringIO.StringIO()
    header = StringIO.StringIO()

    print "[>] Trying to download URL: %s" % url
    # Download file
    try:
        # 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)')
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(pycurl.CONNECTTIMEOUT, 10)
        c.setopt(pycurl.TIMEOUT, 180)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.USERAGENT, 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)')
        c.setopt(c.WRITEFUNCTION, output.write)
        c.setopt(c.HEADERFUNCTION, header.write)
        c.perform()
        # Header parsing
        header_info = header_function(header.getvalue())
    except Exception, e:
        if args.debug:
            traceback.print_exc()
        print_highlighted("[-] Error MESSAGE: %s" % str(e))

    # Write File
    if c.getinfo(c.RESPONSE_CODE) == 200:
        # Check folder
        out_path = os.path.join(os.path.abspath(args.o), host_id)
        if not os.path.exists(out_path):
            os.makedirs(out_path)
        # Output file name
        r = urlparse.urlparse(url)
        filename = r.path.split("/")[-1]
        if filename == "":
            if r.path != "/":
                out_path = os.path.join(out_path, r.path.lstrip("/"))
            filename = "index.dat"
        out_filename = os.path.join(os.path.abspath(out_path), filename)
        # Write file
        try:
            with open(out_filename, 'wb') as f:
                f.write(output.getvalue())
                print_highlighted("[+] Sucessfully saved to FILE: %s" % out_filename)
        except Exception, e:
            if args.debug:
                traceback.print_exc()
            print "[-] Failed to write file %s (use --debug for more info)" % out_filename
    else:
        try:
            print_highlighted("[i] Response CODE: %s MIME_TYPE: %s SIZE: %s" % (
                                  str(c.getinfo(c.RESPONSE_CODE)),
                                  header_info['content-type'],
                                  header_info['content-length'])
                              )
        except Exception, e:
            print_highlighted("[-] Response CODE: %s" % str(c.getinfo(c.RESPONSE_CODE)))

    output.close()


def header_function(header_raw):
    """
    Process header info
    Example from pycurl quick start guide http://pycurl.io/docs/latest/quickstart.html
    :param header_line:
    :return:
    """
    headers = {}
    header_lines = header_raw.splitlines()

    for header_line in header_lines:

        # HTTP standard specifies that headers are encoded in iso-8859-1.
        # On Python 2, decoding step can be skipped.
        # On Python 3, decoding step is required.
        header_line = header_line.decode('iso-8859-1')

        # Header lines include the first status line (HTTP/1.x ...).
        # We are going to ignore all lines that don't have a colon in them.
        # This will botch headers that are split on multiple lines...
        if ':' not in header_line:
            continue

        # Break the header line into header name and value.
        name, value = header_line.split(':', 1)

        # Remove whitespace that may be present.
        # Header lines include the trailing newline, and there may be whitespace
        # around the colon.
        name = name.strip()
        value = value.strip()

        # Header names are case insensitive.
        # Lowercase name here.
        name = name.lower()

        # Now we can actually record the header name and value.
        headers[name] = value

    return headers


def signal_handler(signal, frame):
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)
    sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)
    init(autoreset=False)

    print Style.RESET_ALL + Fore.WHITE + Back.BLUE
    print " ".ljust(80)
    print "   _   ________  _______           __           ".ljust(80)
    print "  | | / /_  __/ / ___/ /  ___ ____/ /_____ ____ ".ljust(80)
    print "  | |/ / / /   / /__/ _ \/ -_) __/  '_/ -_) __/ ".ljust(80)
    print "  |___/ /_/    \___/_//_/\\__/\__/_/\_\\__/_/    ".ljust(80)
    print " ".ljust(80)
    print "  IP and Domain Version                        ".ljust(80)
    print ("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80)
    print " ".ljust(80) + Style.RESET_ALL
    print Style.RESET_ALL + " "

    parser = argparse.ArgumentParser(description='Virustotal Online Checker (IP/Domain)')
    parser.add_argument('-f', help='File to process (hash line by line OR csv with hash in each line - auto-detects '
                                   'position and comment)', metavar='path', default='')
    parser.add_argument('-m', help='Maximum number of items (urls, hosts, samples) to show', metavar='max-items',
                        default=10)
    parser.add_argument('-c', help='Name of the cache database file (default: vt-check-db.pkl)', metavar='cache-db',
                        default='vt-check-db.pkl')
    parser.add_argument('--nocache', action='store_true', help='Do not use the load the cache db (vt-check-cache.pkl)',
                        default=False)
    parser.add_argument('--nocsv', action='store_true', help='Do not write a CSV with the results', default=False)
    parser.add_argument('--recursive', action='store_true', help='Process the resolved IPs as well', default=False)
    parser.add_argument('--download', action='store_true',
                        help='Try to download the URLs (directories with host/ip names)', default=False)
    parser.add_argument('-o', help='Store the downloads to the given directory', metavar='output-folder',
                        default='./')
    parser.add_argument('--dups', action='store_true', help='Do not skip duplicate hashes', default=False)
    parser.add_argument('--noresolve', action='store_true', help='Do not perform DNS resolve test on found domain '
                                                                 'names', default=False)
    parser.add_argument('--ping', action='store_true', help='Perform ping check on IPs (speeds up process if many '
                                                            'public but internally routed IPs appear in text file)',
                        default=False)
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
            print "[+] Analyzed IPs/domains will be written to cache database: {0}".format(args.c)
        print "[+] You can always interrupt the scan by pressing CTRL+C without loosing the scan state"

    # Open input file
    try:
        with open(args.f, 'r') as fh_input:
            lines = fh_input.readlines()
    except Exception, e:
        print "[E] Cannot read input file"
        sys.exit(1)

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
                    fh_results.write(
                        "IP;Rating;Owner;Country Code;Log Line No;Positives;Total;Malicious Samples;Hosts\n")
            except Exception, e:
                print "[E] Cannot write CSV export file: {0}".format(result_file)

    # Process the input lines
    elements = process_lines(lines, args.debug)

    # Process elements
    process_elements(elements, result_file, int(args.m), args.nocsv, args.dups, args.noresolve, args.ping,
                     args.debug)

    # Write Cache
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)

    print Style.RESET_ALL
