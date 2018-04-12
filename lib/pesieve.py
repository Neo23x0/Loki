#!/usr/bin/python
#
# PE-Sieve Integration by @hasherezade

import os
import sys
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
        self.peSieve = os.path.join(workingDir, 'tools/pe-sieve32.exe')
        if is64bit:
            self.peSieve = os.path.join(workingDir, 'tools/pe-sieve64.exe')

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

    def scan(self, pid):
        """
        Performs a scan on a given process ID
        :param pid: process id of the process to check
        :return hooked, replaces, suspicious: number of findings per type
        """
        # Presets
        results = {"hooked": 0, "replaced": 0, "suspicious": 0, "implanted": 0}
        # Compose command
        command = [self.peSieve, '/pid', str(pid), '/ofilter', '2', '/quiet']
        # Run PE-Sieve on given process
        output, returnCode = runProcess(command)

        # Process the output
        lines = output.splitlines()
        start_summary = False
        for line in lines:
            if self.logger.debug:
                if "SUMMARY:" in line:
                    start_summary = True
                if start_summary:
                    print(line)
            # Extract the integer values
            result_hooked = re.search(r'Hooked:[\s\t]+([0-9]+)', line)
            if result_hooked:
                results["hooked"] = int(result_hooked.group(1))
            result_replaced = re.search(r'Replaced:[\s\t]+([0-9]+)', line)
            if result_replaced:
                results["replaced"] = int(result_replaced.group(1))
            result_suspicious = re.search(r'Other suspicious:[\s\t]+([0-9]+)', line)
            if result_suspicious:
                results["suspicious"] = int(result_suspicious.group(1))
            result_implanted = re.search(r'Implanted:[\s\t]+([0-9]+)', line)
            if result_implanted:
                results["implanted"] = int(result_implanted.group(1))
        # Check output for process replacements
        if "SUMMARY:" not in output:
            self.logger.log("ERROR", "PESieve", "Something went wrong during PE-Sieve scan. "
                                                "Couldn't find the SUMMARY section in output.")
        return results
