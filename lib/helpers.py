#!/usr/bin/env python3
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
#  Loki
#  Simple IOC Scanner

import sys
import hashlib
import binascii
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
import threading
import subprocess
import signal
import codecs

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
        # convert string to str in case it's bytes (for python3)
        # TODO: check if that gives the same results as in py2
        string = string.decode("utf-8", errors='ignore')
        nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)

    except Exception as e:
        traceback.print_exc()
        pass
    #print "NON: ", nonascii
    return nonascii


def getPlatformFull():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % ( " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception as e:
        type_info = " ".join(platform.win32_ver())
    return type_info


def setNice(logger):
    try:
        pid = os.getpid()
        p = psutil.Process(pid)
        logger.log("INFO", "Init", "Setting LOKI process with PID: %s to priority IDLE" % pid)
        p.nice(psutil.IDLE_PRIORITY_CLASS)
        return 1
    except Exception as e:
        if logger.debug:
            traceback.print_exc()
        logger.log("ERROR", "Init", "Error setting nice value of THOR process")
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


def removeBinaryZero(string):
    #return re.sub(r'\x00','',string)
    # py2 => py3:
    return string.replace(b'\x00',b'')


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
            bytes_to_read = int(len(str(sig)) / 2) 
            res = res_full[:bytes_to_read]
            if res == bytes.fromhex(sig):
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
            # py2 => py3
            #if isinstance(string, unicode) and not stripit:
            if isinstance(string, str) and not stripit:
                # hmmm, the original version didn't do what the function name says: "remove non ascii":
                #nonascii = string.encode('unicode-escape')
                # ... so this should be ok? to avoid the problem, that any kind of python3 encode messes up the regexes, e.g. \. => \\.
                nonascii = string
            # py2 => py3
            #elif isinstance(string, str) and not stripit:
            elif isinstance(string, bytes) and not stripit:
                nonascii = string.decode('utf-8', 'replace').encode('unicode-escape')
            else:
                try:
                    nonascii = string.encode('raw_unicode_escape')
                except Exception as e:
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


def runProcess(command, timeout=10):
    """
    Run a process and check it's output
    :param command:
    :return output:
    """
    output = ""
    returnCode = 0

    # Kill check
    kill_check = threading.Event()
    def _kill_process_after_a_timeout(pid):
        os.kill(pid, signal.SIGTERM)
        kill_check.set() # tell the main routine that we had to kill
        print("timeout hit - killing pid {0}".format(pid))
        # use SIGKILL if hard to kill...
        return "", 1
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        returnCode = e.returncode
        traceback.print_exc()
    #print p.communicate()[0]
    pid = p.pid
    watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid, ))
    watchdog.start()
    (stdout, stderr) = p.communicate()
    output = "{0} {1}".format(stdout, stderr)
    watchdog.cancel() # if it's still waiting to run
    success = not kill_check.isSet()
    kill_check.clear()

    return output, returnCode

def getHostname(os_platform):
    """
    Generate and return a hostname
    :return:
    """
    # Computername
    if os_platform == "linux" or os_platform == "osx":
        return os.uname()[1]
    else:
        return os.environ['COMPUTERNAME']
