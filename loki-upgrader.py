#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
#  LOKI Upgrader
try:
 from urllib2 import urlopen
except ImportError:
 from urllib.request import urlopen #For python 3.5
import json
import zipfile
import shutil
import io
import os
import argparse
import traceback
from sys import platform as _platform
try:
    from urlparse import urlparse 
except ImportError:
    from urllib.parse import urlparse
from os.path import exists

# Win32 Imports
if _platform == "win32":
    try:
        import win32api
    except Exception:
        platform = "linux"  # crazy guess


from lib.lokilogger import *

# Platform
platform = ""
if _platform == "linux" or _platform == "linux2":
    platform = "linux"
elif _platform == "darwin":
    platform = "macos"
elif _platform == "win32":
    platform = "windows"

def needs_update(sig_url):
    try:
        o=urlparse(sig_url)
        path=o.path.split('/')
        branch=path[4].split('.')[0]
        path.pop(len(path)-1)
        path.pop(len(path)-1)
        url = o.scheme+'://api.'+o.netloc+'/repos'+'/'.join(path)+'/commits/'+branch
        response_info = urlopen(url)
        j = json.load(response_info)
        sha=j['sha']
        cache='_'.join(path)+'.cache'
        changed=False
        if exists(cache):
            with open(cache, "r") as file:
                old_sha = file.read().rstrip()
            if sha != old_sha:
                changed=True
        else:
            with open(cache, "w") as file:
                file.write(sha)
                changed=True
        return changed
    except Exception:
        return True


class LOKIUpdater(object):

    # Incompatible signatures
    INCOMPATIBLE_RULES = []

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]
    
    UPDATE_URL_LOKI = "https://api.github.com/repos/Neo23x0/Loki/releases/latest"
    
    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = application_path

    def update_signatures(self, clean=False):
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                if needs_update(sig_url):
                    # Downloading current repository
                    try:
                        self.logger.log("INFO", "Upgrader", "Downloading %s ..." % sig_url)
                        response = urlopen(sig_url)
                    except Exception:
                        if self.debug:
                            traceback.print_exc()
                        self.logger.log("ERROR", "Upgrader", "Error downloading the signature database - "
                                                            "check your Internet connection")
                        sys.exit(1)

                    # Preparations
                    try:
                        sigDir = os.path.join(self.application_path, os.path.abspath('signature-base/'))
                        if clean:
                            self.logger.log("INFO", "Upgrader", "Cleaning directory '%s'" % sigDir)
                            shutil.rmtree(sigDir)
                        for outDir in ['', 'iocs', 'yara', 'misc']:
                            fullOutDir = os.path.join(sigDir, outDir)
                            if not os.path.exists(fullOutDir):
                                os.makedirs(fullOutDir)
                    except Exception:
                        if self.debug:
                            traceback.print_exc()
                        self.logger.log("ERROR", "Upgrader", "Error while creating the signature-base directories")
                        sys.exit(1)

                    # Read ZIP file
                    try:
                        zipUpdate = zipfile.ZipFile(io.BytesIO(response.read()))
                        for zipFilePath in zipUpdate.namelist():
                            sigName = os.path.basename(zipFilePath)
                            if zipFilePath.endswith("/"):
                                continue
                            # Skip incompatible rules
                            skip = False
                            for incompatible_rule in self.INCOMPATIBLE_RULES:
                                if sigName.endswith(incompatible_rule):
                                    self.logger.log("NOTICE", "Upgrader", "Skipping incompatible rule %s" % sigName)
                                    skip = True
                            if skip:
                                continue
                            # Extract the rules
                            self.logger.log("DEBUG", "Upgrader", "Extracting %s ..." % zipFilePath)
                            if "/iocs/" in zipFilePath and zipFilePath.endswith(".txt"):
                                targetFile = os.path.join(sigDir, "iocs", sigName)
                            elif "/yara/" in zipFilePath and zipFilePath.endswith(".yar"):
                                targetFile = os.path.join(sigDir, "yara", sigName)
                            elif "/misc/" in zipFilePath and zipFilePath.endswith(".txt"):
                                targetFile = os.path.join(sigDir, "misc", sigName)
                            elif zipFilePath.endswith(".yara"):
                                targetFile = os.path.join(sigDir, "yara", sigName)
                            else:
                                continue

                            # New file
                            if not os.path.exists(targetFile):
                                self.logger.log("INFO", "Upgrader", "New signature file: %s" % sigName)

                            # Extract file
                            source = zipUpdate.open(zipFilePath)
                            target = open(targetFile, "wb")
                            with source, target:
                                shutil.copyfileobj(source, target)
                            target.close()
                            source.close()

                    except Exception:
                        if self.debug:
                            traceback.print_exc()
                        self.logger.log("ERROR", "Upgrader", "Error while extracting the signature files from the download "
                                                            "package")
                        sys.exit(1)
                else:
                    self.logger.log("INFO", "Upgrader", "%s is up to date." % sig_url)

        except Exception:
            if self.debug:
                traceback.print_exc()
            return False
        return True


    def update_loki(self):
        try:

            # Downloading the info for latest release
            try:
                self.logger.log("INFO", "Upgrader", "Checking location of latest release %s ..." % self.UPDATE_URL_LOKI)
                response_info = urlopen(self.UPDATE_URL_LOKI)
                data = json.load(response_info)
                # Get download URL
                zip_url = data['assets'][0]['browser_download_url']
                self.logger.log("INFO", "Upgrader", "Downloading latest release %s ..." % zip_url)
                response_zip = urlopen(zip_url)
            except Exception:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Upgrader", "Error downloading the loki update - check your Internet connection")
                sys.exit(1)

            # Read ZIP file
            try:
                zipUpdate = zipfile.ZipFile(io.BytesIO(response_zip.read()))
                for zipFilePath in zipUpdate.namelist():
                    if zipFilePath.endswith("/") or "/config/" in zipFilePath or "/loki-upgrader.exe" in zipFilePath:
                        continue

                    source = zipUpdate.open(zipFilePath)
                    targetFile = "/".join(zipFilePath.split("/")[1:])

                    self.logger.log("INFO", "Upgrader", "Extracting %s ..." %targetFile)

                    try:
                        # Create file if not present
                        if not os.path.exists(os.path.dirname(targetFile)):
                            if os.path.dirname(targetFile) != '':
                                os.makedirs(os.path.dirname(targetFile))
                    except Exception:
                        if self.debug:
                            self.logger.log("DEBUG", "Upgrader", "Cannot create dir name '%s'" % os.path.dirname(targetFile))
                            traceback.print_exc()

                    try:
                        # Create target file
                        target = open(targetFile, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                            if self.debug:
                                self.logger.log("DEBUG", "Upgrader", "Successfully extracted '%s'" % targetFile)
                        target.close()
                    except Exception:
                        self.logger.log("ERROR", "Upgrader", "Cannot extract '%s'" % targetFile)
                        if self.debug:
                            traceback.print_exc()

            except Exception:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Upgrader",
                                "Error while extracting the signature files from the download package")
                sys.exit(1)

        except Exception:
            if self.debug:
                traceback.print_exc()
            return False
        return True


def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and platform == "windows":
            # print "Trying to translate"
            # print application_path
            application_path = win32api.GetLongPathName(application_path)
        #if args.debug:
        #    logger.log("DEBUG", "Init", "Application Path: %s" % application_path)
        return application_path
    except Exception:
        print("Error while evaluation of application path")
        traceback.print_exc()


if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='Loki - Upgrader')
    parser.add_argument('-l', help='Log file', metavar='log-file', default='loki-upgrade.log')
    parser.add_argument('--sigsonly', action='store_true', help='Update the signatures only', default=False)
    parser.add_argument('--progonly', action='store_true', help='Update the program files only', default=False)
    parser.add_argument('--nolog', action='store_true', help='Don\'t write a local log file', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--clean', action='store_true', default=False, help='Clean up the signature directory and get '
                                                                            'a fresh set')
    parser.add_argument('--detached', action='store_true', default=False, help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Computername
    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]

    # Logger
    logger = LokiLogger(args.nolog, args.l, t_hostname, '', '', False, False, False, args.debug, platform=platform, caller='upgrader')

    # Update LOKI
    updater = LOKIUpdater(args.debug, logger, get_application_path())

    if not args.sigsonly:
        logger.log("INFO", "Upgrader", "Updating LOKI ...")
        updater.update_loki()
    if not args.progonly:
        logger.log("INFO", "Upgrader", "Updating Signatures ...")
        updater.update_signatures(args.clean)

    logger.log("INFO", "Upgrader", "Update complete")

    if args.detached:
        logger.log("INFO", "Upgrader", "Press any key to return ...")

    sys.exit(0)
