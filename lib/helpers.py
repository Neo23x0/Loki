#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
#  Loki
#  Simple IOC Scanner

import sys
import hashlib
import binascii
import pylzma
import zlib
import struct
import socket
import traceback
import os
import re
import psutil
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import netaddr
import datetime
import platform
import time

# Helper Functions -------------------------------------------------------------

def is_ip(string):
    try:
        if netaddr.valid_ipv4(string):
            return True
        if netaddr.valid_ipv6(string):
            return True
        return False
    except:
        traceback.print_exc()
        return False


def is_cidr(string):
    try:
        if netaddr.IPNetwork(string) and "/" in string:
            return True
        return False
    except:
        return False


def ip_in_net(ip, network):
    try:
        # print "Checking if ip %s is in network %s" % (ip, network)
        if netaddr.IPAddress(ip) in netaddr.IPNetwork(network):
            return True
        return False
    except:
        return False


def generateHashes(filedata):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filedata)
        sha1.update(filedata)
        sha256.update(filedata)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception as e:
        traceback.print_exc()
        return 0, 0, 0


def removeNonAsciiDrop(string):
    nonascii = "error"
    #print "CON: ", string
    try:
        # Generate a new string without disturbing characters
        nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)

    except Exception, e:
        traceback.print_exc()
        pass
    #print "NON: ", nonascii
    return nonascii


def getPlatformFull():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % ( " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception, e:
        type_info = " ".join(platform.win32_ver())
    return type_info


def setNice(logger):
    try:
        pid = os.getpid()
        p = psutil.Process(pid)
        logger.log("INFO", "Setting LOKI process with PID: %s to priority IDLE" % pid)
        p.nice(psutil.IDLE_PRIORITY_CLASS)
        return 1
    except Exception, e:
        if logger.debug:
            traceback.print_exc()
        logger.log("ERROR", "Error setting nice value of THOR process")
        return 0


def getExcludedMountpoints():
    excludes = []
    try:
        mtab = open("/etc/mtab", "r")
        for mpoint in mtab:
            options = mpoint.split(" ")
            if not options[0].startswith("/dev/"):
                if not options[1] == "/":
                    excludes.append(options[1])
    except Exception as e:
        print ("Error while reading /etc/mtab")
    finally:
        mtab.close()
    return excludes


def decompressSWFData(in_data):
    try:
        ver = in_data[3]

        if in_data[0] == 'C':
            # zlib SWF
            decompressData = zlib.decompress(in_data[8:])
        elif in_data[0] == 'Z':
            # lzma SWF
            decompressData = pylzma.decompress(in_data[12:])
        elif in_data[0] == 'F':
            # uncompressed SWF
            decompressData = in_data[8:]

        header = list(struct.unpack("<8B", in_data[0:8]))
        header[0] = ord('F')
        return True, struct.pack("<8B", *header) + decompressData

    except Exception as e:
        traceback.print_exc()
        return False, "Decompression error"


def removeBinaryZero(string):
    return re.sub(r'\x00','',string)


def printProgress(i):
    if (i%4) == 0:
        sys.stdout.write('\b/')
    elif (i%4) == 1:
        sys.stdout.write('\b-')
    elif (i%4) == 2:
        sys.stdout.write('\b\\')
    elif (i%4) == 3:
        sys.stdout.write('\b|')
    sys.stdout.flush()


def transformOS(regex, platform):
    # Replace '\' with '/' on Linux/Unix/OSX
    if platform != "windows":
        regex = regex.replace(r'\\', r'/')
        regex = regex.replace(r'C:', '')
    return regex


def replaceEnvVars(path):

    # Setting new path to old path for default
    new_path = path

    # ENV VARS ----------------------------------------------------------------
    # Now check if an environment env is included in the path string
    res = re.search(r"([@]?%[A-Za-z_]+%)", path)
    if res:
        env_var_full = res.group(1)
        env_var = env_var_full.replace("%", "").replace("@", "")

        # Check environment varibales if there is a matching var
        if env_var in os.environ:
            if os.environ[env_var]:
                new_path = path.replace(env_var_full, re.escape(os.environ[env_var]))

    # TYPICAL REPLACEMENTS ----------------------------------------------------
    if path[:11].lower() == "\\systemroot":
        new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])

    if path[:8].lower() == "system32":
        new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])

    #if path != new_path:
    #    print "OLD: %s NEW: %s" % (path, new_path)
    return new_path


def get_file_type(filePath, filetype_sigs, max_filetype_magics, logger):
    try:
        # Reading bytes from file
        res_full = open(filePath, 'rb', os.O_RDONLY).read(max_filetype_magics)
        # Checking sigs
        for sig in filetype_sigs:
            bytes_to_read = len(str(sig)) / 2
            res = res_full[:bytes_to_read]
            if res == sig.decode('hex'):
                return filetype_sigs[sig]
        return "UNKNOWN"
    except Exception as e:
        if logger.debug:
            traceback.print_exc()
        return "UNKNOWN"


def removeNonAscii(string, stripit=False):
    nonascii = "error"

    try:
        try:
            # Handle according to the type
            if isinstance(string, unicode) and not stripit:
                nonascii = string.encode('unicode-escape')
            elif isinstance(string, str) and not stripit:
                nonascii = string.decode('utf-8', 'replace').encode('unicode-escape')
            else:
                try:
                    nonascii = string.encode('raw_unicode_escape')
                except Exception, e:
                    nonascii = str("%s" % string)

        except Exception as e:
            # traceback.print_exc()
            # print "All methods failed - removing characters"
            # Generate a new string without disturbing characters
            nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)

    except Exception as e:
        traceback.print_exc()
        pass

    return nonascii

def getAge(filePath):
    try:
        stats=os.stat(filePath)

        # Created
        ctime=stats.st_ctime
        # Modified
        mtime=stats.st_mtime
        # Accessed
        atime=stats.st_atime

    except Exception as e:
        # traceback.print_exc()
        return (0, 0, 0)

    # print "%s %s %s" % ( ctime, mtime, atime )
    return (ctime, mtime, atime)

def getAgeString(filePath):
    ( ctime, mtime, atime ) = getAge(filePath)
    timestring = ""
    try:
        timestring = "CREATED: %s MODIFIED: %s ACCESSED: %s" % ( time.ctime(ctime), time.ctime(mtime), time.ctime(atime) )
    except Exception as e:
        timestring = "CREATED: not_available MODIFIED: not_available ACCESSED: not_available"
    return timestring
