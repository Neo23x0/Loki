# -*- coding: utf-8 -*-
#
# LOKI Logger

import sys
import re
from colorama import Fore, Back, Style
from colorama import init
import codecs
import datetime
import traceback
import rfc5424logging
import logging
from logging import handlers
import socket

__version__ = '0.51.0'


# Logger Class -----------------------------------------------------------------
class LokiLogger:

    STDOUT_CSV = 0
    STDOUT_LINE = 1
    FILE_CSV = 2
    FILE_LINE = 3
    SYSLOG_LINE = 4

    no_log_file = False
    log_file = "loki.log"
    csv = False
    hostname = "NOTSET"
    alerts = 0
    warnings = 0
    notices = 0
    messagecount = 0
    only_relevant = False
    remote_logging = False
    debug = False
    linesep = "\n"

    def __init__(self, no_log_file, log_file, hostname, remote_host, remote_port, syslog_tcp, csv, only_relevant, debug, platform, caller, customformatter=None):
        self.version = __version__
        self.no_log_file = no_log_file
        self.log_file = log_file
        self.hostname = hostname
        self.csv = csv
        self.only_relevant = only_relevant
        self.debug = debug
        self.caller = caller
        self.CustomFormatter = customformatter
        if "windows" in platform.lower():
            self.linesep = "\r\n"

        # Colorization ----------------------------------------------------
        init()

        # Welcome
        if not self.csv:
            self.print_welcome()

        # Syslog server target
        if remote_host:
            try:
                # Create remote logger
                self.remote_logger = logging.getLogger('LOKI')
                self.remote_logger.setLevel(logging.DEBUG)
                socket_type = socket.SOCK_STREAM if syslog_tcp else socket.SOCK_DGRAM
                remote_syslog_handler = rfc5424logging.Rfc5424SysLogHandler(address=(remote_host, remote_port),
                                                                            facility=handlers.SysLogHandler.LOG_LOCAL3,
                                                                            socktype=socket_type)
                self.remote_logger.addHandler(remote_syslog_handler)
                self.remote_logging = True
            except Exception as e:
                print('Failed to create remote logger: ' + str(e))
                sys.exit(1)

    def log(self, mes_type, module, message):

        if not self.debug and mes_type == "DEBUG":
            return

        # Counter
        if mes_type == "ALERT":
            self.alerts += 1
        if mes_type == "WARNING":
            self.warnings += 1
        if mes_type == "NOTICE":
            self.notices += 1
        self.messagecount += 1

        if self.only_relevant:
            if mes_type not in ('ALERT', 'WARNING'):
                return

        # to file
        if not self.no_log_file:
            self.log_to_file(message, mes_type, module)

        # to stdout
        try:
            self.log_to_stdout(message, mes_type)
        except Exception:
            print ("Cannot print certain characters to command line - see log file for full unicode encoded log line")
            self.log_to_stdout(message, mes_type)

        # to syslog server
        if self.remote_logging:
            self.log_to_remotesys(message, mes_type, module)

    def Format(self, type, message, *args):
        if not self.CustomFormatter:
            return message.format(*args)
        else:
            return self.CustomFormatter(type, message, args)

    def log_to_stdout(self, message, mes_type):

        if self.csv:
            print(self.Format(self.STDOUT_CSV, '{0},{1},{2},{3}', getSyslogTimestamp(), self.hostname, mes_type, message))

        else:
            try:
                reset_all = Style.NORMAL+Fore.RESET
                key_color = Fore.WHITE
                base_color = Back.BLACK+Fore.WHITE
                high_color = Fore.WHITE+Back.BLACK

                if mes_type == "NOTICE":
                    base_color = Fore.CYAN+''+Back.BLACK
                    high_color = Fore.BLACK+''+Back.CYAN
                elif mes_type == "INFO":
                    base_color = Fore.GREEN+''+Back.BLACK
                    high_color = Fore.BLACK+''+Back.GREEN
                elif mes_type == "WARNING":
                    base_color = Fore.YELLOW+''+Back.BLACK
                    high_color = Fore.BLACK+''+Back.YELLOW
                elif mes_type == "ALERT":
                    base_color = Fore.RED+''+Back.BLACK
                    high_color = Fore.BLACK+''+Back.RED
                elif mes_type == "DEBUG":
                    base_color = Fore.WHITE+''+Back.BLACK
                    high_color = Fore.BLACK+''+Back.WHITE
                elif mes_type == "ERROR":
                    base_color = Fore.MAGENTA+''+Back.BLACK
                    high_color = Fore.WHITE+''+Back.MAGENTA
                elif mes_type == "RESULT":
                    if "clean" in message.lower():
                        high_color = Fore.BLACK+Back.GREEN
                        base_color = Fore.GREEN+Back.BLACK
                    elif "suspicious" in message.lower():
                        high_color = Fore.BLACK+Back.YELLOW
                        base_color = Fore.YELLOW+Back.BLACK
                    else:
                        high_color = Fore.BLACK+Back.RED
                        base_color = Fore.RED+Back.BLACK

                # Colorize Type Word at the beginning of the line
                type_colorer = re.compile(r'([A-Z]{3,})', re.VERBOSE)
                mes_type = type_colorer.sub(high_color+r'[\1]'+base_color, mes_type)
                # Break Line before REASONS
                linebreaker = re.compile('(MD5:|SHA1:|SHA256:|MATCHES:|FILE:|FIRST_BYTES:|DESCRIPTION:|REASON_[0-9]+)', re.VERBOSE)
                message = linebreaker.sub(r'\n\1', message)
                # Colorize Key Words
                colorer = re.compile('([A-Z_0-9]{2,}:)\s', re.VERBOSE)
                message = colorer.sub(key_color+Style.BRIGHT+r'\1 '+base_color+Style.NORMAL, message)

                # Print to console
                if mes_type == "RESULT":
                    res_message = "\b\b%s %s" % (mes_type, message)
                    print(base_color+' '+res_message+' '+Back.BLACK)
                    print(Fore.WHITE+' '+Style.NORMAL)
                else:
                    sys.stdout.write("%s%s\b\b%s %s%s%s%s\n" % (reset_all, base_color, mes_type, message, Back.BLACK,Fore.WHITE,Style.NORMAL))

            except Exception:
                if self.debug:
                    traceback.print_exc()
                    sys.exit(1)
                print("Cannot print to cmd line - formatting error")

    def log_to_file(self, message, mes_type, module):
        try:
            # Write to file
            with codecs.open(self.log_file, "a", encoding='utf-8') as logfile:
                if self.csv:
                    logfile.write(self.Format(self.FILE_CSV, u"{0},{1},{2},{3},{4}{5}", getSyslogTimestamp(), self.hostname, mes_type, module, message, self.linesep))
                else:
                    logfile.write(self.Format(self.FILE_LINE, u"{0} {1} LOKI: {2}: MODULE: {3} MESSAGE: {4}{5}", getSyslogTimestamp(), self.hostname, mes_type.title(), module, message, self.linesep))
        except Exception:
            if self.debug:
                traceback.print_exc()
                sys.exit(1)
            print("Cannot print line to log file {0}".format(self.log_file))

    def log_to_remotesys(self, message, mes_type, module):
        # Preparing the message
        syslog_message = self.Format(self.SYSLOG_LINE, "LOKI: {0}: MODULE: {1} MESSAGE: {2}", mes_type.title(), module, message)
        try:
            # Mapping LOKI's levels to the syslog levels
            if mes_type == "NOTICE":
                self.remote_logger.info(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "INFO":
                self.remote_logger.info(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "WARNING":
                self.remote_logger.warning(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "ALERT":
                self.remote_logger.critical(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "DEBUG":
                self.remote_logger.debug(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "ERROR":
                self.remote_logger.error(syslog_message, extra={'msgid': str(self.messagecount)})
        except Exception as e:
            if self.debug:
                traceback.print_exc()
                sys.exit(1)
            print("Error while logging to remote syslog server ERROR: %s" % str(e))

    def print_welcome(self):

        if self.caller == 'main':
            print(str(Back.WHITE))
            print(" ".ljust(79) + Back.BLACK + Style.BRIGHT)

            print("      __   ____  __ ______  ")
            print("     / /  / __ \\/ //_/  _/  ")
            print("    / /__/ /_/ / ,< _/ /    ")
            print("   /____/\\____/_/|_/___/    ")
            print("   YARA and IOC Scanner     ")
            print("  ")
            print("   by Florian Roth, GNU General Public License")
            print("   version %s (Python 3 release)" % __version__)
            print("  ")
            print("   DISCLAIMER - USE AT YOUR OWN RISK")
            print(str(Back.WHITE))
            print(" ".ljust(79) + Back.BLACK + Fore.GREEN)
            print(Fore.WHITE+''+Back.BLACK)

        else:
            print("  ")
            print(Back.GREEN + " ".ljust(79) + Back.BLACK + Fore.GREEN)

            print("  ")
            print("  LOKI UPGRADER ")

            print("  ")
            print(Back.GREEN + " ".ljust(79) + Back.BLACK)
            print(Fore.WHITE + '' + Back.BLACK)


def getSyslogTimestamp():
    date_obj = datetime.datetime.utcnow()
    date_str = date_obj.strftime("%Y%m%dT%H:%M:%SZ")
    return date_str
