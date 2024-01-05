#!/usr/bin/python
#
# PE-Sieve Integration by @hasherezade

import os
import json
import traceback

from lib.lokilogger import *
from lib.helpers import runProcess

class PESieve(object):
    """
    PESieve class makes use of hasherezade's PE-Sieve tool to scans a given process,
    searching for the modules containing in-memory code modifications
    """
    active = False

    def __init__(self, workingDir, is64bit, logger):

        # Logger
        self.logger = logger
        # PE-Sieve tools
        self.peSieve = os.path.join(workingDir, 'tools/pe-sieve32.exe'.replace("/", os.sep))
        if is64bit:
            self.peSieve = os.path.join(workingDir, 'tools/pe-sieve64.exe'.replace("/", os.sep))

        if self.isAvailable():
            self.active = True
            self.logger.log("NOTICE", "PESieve", "PE-Sieve successfully initialized BINARY: {0} "
                                      "SOURCE: https://github.com/hasherezade/pe-sieve".format(self.peSieve))
        else:
            self.logger.log("NOTICE", "PESieve", "Cannot find PE-Sieve in expected location {0} "
                                      "SOURCE: https://github.com/hasherezade/pe-sieve".format(self.peSieve))

    def isAvailable(self):
        """
        Checks if the PE-Sieve tools are available in a "./tools" sub folder
        :return:
        """
        if not os.path.exists(self.peSieve):
            self.logger.log("DEBUG", "PESieve", "PE-Sieve not found in location '{0}' - "
                                     "feature will not be active".format(self.peSieve))
            return False
        return True

    def scan(self, pid, pesieveshellc = False):
        """
        Performs a scan on a given process ID
        :param pid: process id of the process to check
        :return hooked, replaces, suspicious: number of findings per type
        """
        # Presets
        results = {"patched": 0, "replaced": 0, "unreachable_file": 0, "implanted_pe": 0, "implanted_shc": 0}
        # Compose command
        command = [self.peSieve, '/pid', str(pid), '/ofilter', '2', '/quiet', '/json'] + (['/shellc'] if pesieveshellc else [])
        # Run PE-Sieve on given process
        (output, returnCode) = runProcess(command)
        # Debug output
        if self.logger.debug:
            print("PE-Sieve JSON output: %s" % output)
        if output == '' or not output:
            return results
        try:
            results_raw = json.loads(output)
            #results = results_raw["scan_report"]["scanned"]["modified"]
            results = results_raw["scanned"]["modified"]
        except ValueError:
            traceback.print_exc()
            self.logger.log("DEBUG", "PESieve", "Couldn't parse the JSON output.")
        except Exception:
            traceback.print_exc()
            self.logger.log("ERROR", "PESieve", "Something went wrong during PE-Sieve scan.")
        return results
