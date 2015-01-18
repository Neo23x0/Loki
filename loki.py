#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Loki
# Simple IOC Scanner
#
# Detection is based on three detection methods:
#
# 1. File Name IOC
#    Applied to file names
#
# 2. Yara Check
#    Applied to files and processes
#
# 3. Hash Check
#    Compares known malicious hashes with th ones of the scanned files
#
# Loki combines all IOCs from ReginScanner and SkeletonKeyScanner and is the
# little brother of THOR our full-featured corporate APT Scanner
# 
# Florian Roth
# BSK Consulting GmbH
# January 2015
# v0.2
# 
# DISCLAIMER - USE AT YOUR OWN RISK.

import sys
import os
import argparse
import scandir
import traceback
import yara
import hashlib
import wmi
import re
import datetime
from colorama import Fore, Back, Style
from colorama import init

def scanPath(path, yara_rules, filename_iocs, hashes, false_hashes):
	
	# Startup
	log("INFO","Scanning %s ...  " % path)
	# Compromised marker
	compromised = False
	c = 0

	for root, directories, files in scandir.walk(path, onerror=walkError, followlinks=False):

			# Loop through files
			for filename in files:
				try:

					# Get the file and path
					filePath = os.path.join(root,filename)

					# Print files
					if args.printAll:
						log("DEBUG", "Scanning %s" % filePath)

					# Counter
					c += 1

					if not args.noindicator:
						printProgress(c)

					file_size = os.stat(filePath).st_size
					# print file_size

					# File Name Checks -------------------------------------------------
					for regex in filename_iocs.keys():
						match = re.search(r'%s' % regex, filePath)
						if match:
							description = filename_iocs[regex]
							log("ALERT", "File Name PATTERN: %s DESC: %s MATCH: %s" % (regex, description, filePath))
							compromised = True

					# Hash Check -------------------------------------------------------
					if file_size > ( args.s * 1024):
						continue

					# Read file complete
					with open(filePath, 'rb') as f:
						fileData = f.read()

					md5, sha1, sha256 = generateHashes(fileData)

					if args.debug:
						log("DEBUG", "MD5: %s SHA1: %s SHA256: %s FILE: %s" % ( md5, sha1, sha256, filePath ))

					# False Positive Hash
					if md5 in false_hashes.keys() or sha1 in false_hashes.keys() or sha256 in false_hashes.keys():
						continue

					# Malware Hash
					matchType = None
					matchDesc = None
					matchHash = None
					if md5 in hashes.keys():
						matchType = "MD5"
						matchDesc = hashes[md5]
						matchHash = md5
					elif sha1 in hashes.keys():
						matchType = "SHA1"
						matchDesc = hashes[sha1]
						matchHash = sha1
					elif sha256 in hashes.keys():
						matchType = "SHA256"
						matchDesc = hashes[sha256]
						matchHash = sha256

					if matchType:
						log("ALERT", "Malware Hash TYPE: %s HASH: %s FILE: %s DESC: %s" % ( matchType, matchHash, filePath, matchDesc))
						compromised = True

					# Yara Check -------------------------------------------------------
					if 'yara_rules' in locals():
						try:
							matches = yara_rules.match(data=fileData)
							if matches:
								for match in matches:
									log("ALERT", "Yara Rule MATCH: %s FILE: %s" % ( match.rule, filePath))
									compromised = True
						except Exception, e:
							if args.debug:
								traceback.print_exc()

				except Exception, e:
					if args.debug:
						traceback.print_exc()

	# Return result
	return compromised


def scanProcesses(rules, filename_iocs):
	# WMI Handler
	c = wmi.WMI()
	processes = c.Win32_Process()

	compromised = False

	for process in processes:

		try:
			pid = process.ProcessId
			name = process.Name
			cmd = process.CommandLine
			if not cmd:
				cmd = "N/A"
			if not name:
				name = "N/A"
		except Exception, e:
			log("ALERT", "Error getting all process information. Did you run the scanner 'As Administrator'?")
			continue

		if pid == 0 or pid == 4:
			log("INFO", "[INFO] Skipping Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))
			continue

		log("NOTICE", "Scanning Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))

		# Psexec command check
		# Skeleton Key Malware Process
		if re.search(r'psexec .* [a-fA-F0-9]{32}', cmd, re.IGNORECASE):
			log("WARNING", "Process that looks liks SKELETON KEY psexec execution detected PID: %s NAME: %s CMD: %s" % ( pid, name, cmd))
			compromised = True

		# Yara rule match
		try:
			matches = rules.match(pid=pid)
			if matches:
				for match in matches:
					log("ALERT", "Yara Rule MATCH: %s PID: %s NAME: %s CMD:%" % ( match.rule, pid, name, cmd))
					compromised = True
		except Exception, e:
			log("ERROR", "Error while process memory Yara check (maybe the process doesn't exist anymore or access denied). PID: %s NAME: %s" % ( pid, name))

	return compromised


def generateHashes(filedata):
	try:
		md5 = hashlib.md5()
		sha1 = hashlib.sha1()
		sha256 = hashlib.sha256()
		md5.update(filedata)
		sha1.update(filedata)
		sha256.update(filedata)
		return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
	except Exception, e:
		traceback.print_exc()
		return 0, 0, 0


def walkError(err):
	if args.debug:
		traceback.print_exc()


def getFileNameIOCs(ioc_file):

	filenames = {}

	try:
		with open(ioc_file, 'r') as file:
			lines = file.readlines()

		for line in lines:
			try:
				# Comments
				if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
					continue
				# Elements with description
				if ";" in line:
					row = line.split(';')
					regex = row[0]
					desc  = row[1].rstrip(" ").rstrip("\n")
				# Elements without description
				else:
					regex = line
				filenames[regex] = desc
			except Exception, e:
				log("ERROR", "Error reading line: %s" % line)

	except Exception, e:
		traceback.print_exc()
		log("ERROR", "Error reading File IOC file: %s" % ioc_file)

	return filenames


def getHashes(hash_file):

	hashes = {}

	try:
		with open(hash_file, 'r') as file:
			lines = file.readlines()

		for line in lines:
			try:
				if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
					continue
				row = line.split(';')
				hash = row[0]
				comment = row[1].rstrip(" ").rstrip("\n")
				# Empty File Hash
				if hash == "d41d8cd98f00b204e9800998ecf8427e" or \
				   hash == "da39a3ee5e6b4b0d3255bfef95601890afd80709" or \
				   hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
					continue
				# Else - check which type it is
				if len(hash) == 32 or len(hash) == 40 or len(hash) == 64:
					hashes[hash.lower()] = comment
			except Exception,e:
				log("ERROR", "Cannot read line: %s" % line)

	except Exception, e:
		traceback.print_exc()
		log("ERROR", "Error reading Hash file: %s" % hash_file)

	return hashes


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


def log(mes_type, message):

	try:
		# Default
		color = Fore.WHITE
		# Print to console
		if mes_type == "ERROR":
			color = Fore.MAGENTA
		if mes_type == "INFO":
			color = Fore.GREEN + Style.BRIGHT
		if mes_type == "ALERT":
			color = Fore.RED
		if mes_type == "DEBUG":
			color = Fore.WHITE
		if mes_type == "WARNING":
			color = Fore.YELLOW
		if mes_type == "NOTICE":
			color = Fore.CYAN

		print color, "\b[%s] %s" % (mes_type, message), Fore.WHITE, Style.NORMAL

		# Write to file
		with open(args.l, "a") as logfile:
			logfile.write("%s %s LOKI: %s\n" % (getSyslogTimestamp(), t_hostname, message))

	except Exception, e:
		traceback.print_exc()
		print "Cannot print log file"


def getSyslogTimestamp():
	date_obj = datetime.datetime.now()
	date_str = date_obj.strftime("%b %d %H:%M:%S")
	daymod = re.compile('^([A-Z][a-z][a-z]) 0([0-9])')
	date_str_mod = daymod.sub(r"\1  \2", date_str)
	return date_str_mod


def printWelcome():
	print Back.GREEN, "                                                                    ", Back.BLACK
	print "  "
	print "   " + Back.GREEN + "  " + Back.BLACK + "      " + Back.GREEN + "      " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK
	print "   " + Back.GREEN + "  " + Back.BLACK + "      " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "    " + Back.BLACK + "    " + Back.GREEN + "  " + Back.BLACK
	print "   " + Back.GREEN + "      " + Back.BLACK + "  " + Back.GREEN + "      " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK
	print "  "
	print "  Simple IOC Scanner"
	print "  "
	print "  (C) Florian Roth - BSK Consulting GmbH"
	print "  Jan 2015"
	print "  Version 0.2"
	print "  "
	print "  DISCLAIMER - USE AT YOUR OWN RISK"
	print "  "
	print Back.GREEN, "                                                                    ", Back.BLACK
	print Fore.WHITE+''+Back.BLACK


# MAIN ################################################################
if __name__ == '__main__':

	# Parse Arguments
	parser = argparse.ArgumentParser(description='Loki - Simple IOC Scanner')
	parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\')
	parser.add_argument('-s', help='Maximum file site to check in KB (default 2000 KB)', metavar='kilobyte', default=2048)
	parser.add_argument('-l', help='Log file', metavar='log-file', default='loki.log')
	parser.add_argument('--printAll', action='store_true', help='Print all files that are scanned', default=False)
	parser.add_argument('--noprocscan', action='store_true', help='Skip the process scan', default=False)
	parser.add_argument('--nofilescan', action='store_true', help='Skip the file scan', default=False)
	parser.add_argument('--noindicator', action='store_true', help='Do not show a progress indicator', default=False)
	parser.add_argument('--dontwait', action='store_true', help='Do not wait on exit', default=False)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

	args = parser.parse_args()

	# Colorization ----------------------------------------------------
	init()

	# Remove old log file
	if os.path.exists(args.l):
		os.remove(args.l)

	# Print Welcome ---------------------------------------------------
	printWelcome()
	t_hostname = os.environ['COMPUTERNAME']
	log("INFO", "LOKI - Starting Loki Scan on %s" % t_hostname)

	# Read IOCs -------------------------------------------------------
	# File Name IOCs
	filename_iocs = getFileNameIOCs('filename-iocs.txt')
	log("INFO","File Name Characteristics initialized with %s regex patterns" % len(filename_iocs.keys()))
	# Hash based IOCs
	hashes = getHashes('hash-iocs.txt')
	log("INFO","Malware Hashes initialized with %s hashes" % len(hashes.keys()))
	# Hash based False Positives
	false_hashes = getHashes('falsepositive-hashes.txt')
	log("INFO","False Positive Hashes initialized with %s hashes" % len(false_hashes.keys()))
	# Compile Yara Rules
	if os.path.exists('yara_rules.yar'):
		yara_rules = yara.compile('yara_rules.yar')
	else:
		log("INFO","Place the yara rule file 'yara_rules.yar' in the program folder to enable Yara scanning.")

	# Scan Processes --------------------------------------------------
	result_proc = False
	if not args.noprocscan:
		result_proc = scanProcesses(yara_rules, filename_iocs)

	# Scan Path -------------------------------------------------------
	result_path = False
	if not args.nofilescan:
		result_path = scanPath(args.p, yara_rules, filename_iocs, hashes, false_hashes)

	# Result ----------------------------------------------------------
	if result_path or result_proc:
		log("INFO", "INDICATORS DETECTED!")
	else:
		log("INFO", "SYSTEM SEEMS TO BE CLEAN.")

	print " "
	if not args.dontwait:
		raw_input("Press Enter to exit ...")