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
# v0.1
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
from colorama import Fore, Back, Style
from colorama import init

def scanPath(path, yara_rules, filename_iocs, hashes, false_hashes):
	
	# Startup
	print Fore.CYAN,"[INFO] Scanning %s ...  " % path, Fore.WHITE
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
						print "[DEBUG] Scanning %s" % filePath

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
							print Fore.RED, "\b[FOUND] File Name PATTERN: %s DESC: %s MATCH: %s" % (regex, description, filePath), Fore.WHITE
							compromised = True

					# Hash Check -------------------------------------------------------
					if file_size > ( args.s * 1024):
						continue

					# Read file complete
					with open(filePath, 'rb') as f:
						fileData = f.read()

					md5, sha1, sha256 = generateHashes(fileData)

					if args.debug:
						print "[DEBUG] MD5: %s SHA1: %s SHA256: %s FILE: %s" % ( md5, sha1, sha256, filePath )

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
						print Fore.RED, "\b[FOUND] Malware Hash TYPE: %s HASH: %s FILE: %s DESC: %s" % ( matchType, matchHash, filePath, matchDesc), Fore.WHITE
						compromised = True

					# Yara Check -------------------------------------------------------
					if 'yara_rules' in locals():
						try:
							matches = yara_rules.match(filePath)
							if matches:
								for match in matches:
									print Fore.RED, "\b[FOUND] Yara Rule MATCH: %s FILE: %s" % ( match.rule, filePath), Fore.WHITE
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
			print Fore.MAGENTA, "[ERROR] Error getting all process information. Did you run the scanner 'As Administrator'?", Fore.WHITE
			continue

		if pid == 0 or pid == 4:
			print Fore.CYAN, "[INFO] Skipping Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ), Fore.WHITE
			continue

		print Fore.GREEN, "[INFO] Scanning Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ), Fore.WHITE

		# Psexec command check
		# Skeleton Key Malware Process
		if re.search(r'psexec .* [a-fA-F0-9]{32}', cmd, re.IGNORECASE):
			print Fore.RED, "\b[MATCH] Process that looks liks SKELETON KEY psexec execution detected PID: %s NAME: %s CMD: %s" % ( pid, name, cmd), Fore.WHITE
			compromised = True
		
		# Yara rule match
		try:
			matches = rules.match(pid=pid)
			if matches:
				for match in matches:
					print Fore.RED, "\b[MATCH] Yara Rule MATCH: %s PID: %s NAME: %s CMD:%" % ( match.rule, pid, name, cmd), Fore.WHITE
					compromised = True			
		except Exception, e:
			print Fore.MAGENTA, "[ERROR] Error while process memory Yara check (maybe the process doesn't exist anymore or access denied). PID: %s NAME: %s" % ( pid, name), Fore.WHITE

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
				print "[ERROR] Error reading line: %s" % line

	except Exception, e:
		traceback.print_exc()
		print "[ERROR] Error reading File IOC file: %s" % ioc_file

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
				print "[ERROR] Cannot read line: %s" % line

	except Exception, e:
		traceback.print_exc()
		print "[ERROR] Error reading Hash file: %s" % hash_file

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

				
def printWelcome():
	print Back.CYAN, "                                                                    ", Back.BLACK
	print Fore.CYAN
	print "   _     ___  _  _____"
	print "  | |   / _ \| |/ /_ _|"
	print "  | |  | | | | ' / | |"
	print "  | |__| |_| | . \ | |"
	print "  |_____\___/|_|\_\___|"

	print "  Simple IOC Scanner"
	print "  "
	print "  (C) Florian Roth - BSK Consulting GmbH"
	print "  Jan 2015"
	print "  Version 0.1"
	print "  "
	print "  DISCLAIMER - USE AT YOUR OWN RISK"
	print "  "
	print Back.CYAN, "                                                                    ", Back.BLACK
	print Fore.WHITE+''+Back.BLACK	


# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='Loki - Simple IOC Scanner')
	parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\')
	parser.add_argument('-s', help='Maximum file site to check in KB (default 2000 KB)', metavar='kilobyte', default=2048)
	parser.add_argument('--printAll', action='store_true', help='Print all files that are scanned', default=False)
	parser.add_argument('--noprocscan', action='store_true', help='Skip the process scan', default=False)
	parser.add_argument('--nofilescan', action='store_true', help='Skip the file scan', default=False)
	parser.add_argument('--noindicator', action='store_true', help='Do not show a progress indicator', default=False)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# Colorization ----------------------------------------------------
	init()
	
	# Print Welcome ---------------------------------------------------
	printWelcome()

	# Read IOCs -------------------------------------------------------
	# File Name IOCs
	filename_iocs = getFileNameIOCs('filename-iocs.txt')
	print Fore.CYAN,"[INFO] File Name Characteristics initialized with %s hashes" % len(filename_iocs.keys()), Fore.WHITE
	# Hash based IOCs
	hashes = getHashes('hash-iocs.txt')
	print Fore.CYAN,"[INFO] Malware Hashes initialized with %s hashes" % len(hashes.keys()), Fore.WHITE
	# Hash based False Positives
	false_hashes = getHashes('falsepositive-hashes.txt')
	print Fore.CYAN,"[INFO] False Positive Hashes initialized with %s hashes" % len(false_hashes.keys()), Fore.WHITE
	# Compile Yara Rules
	if os.path.exists('yara_rules.yar'):
		yara_rules = yara.compile('yara_rules.yar')
	else: 
		print Fore.CYAN,"[INFO] Place the yara rule file 'yara_rules.yar' in the program folder to enable Yara scanning.", Fore.WHITE

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
		print Fore.RED+''+Back.BLACK
		print "\b[RESULT] INDICATORS DETECTED!"
		print Fore.WHITE+''+Back.BLACK
	else:
		print Fore.GREEN+''+Back.BLACK
		print "\b[RESULT] SYSTEM SEEMS TO BE CLEAN. :)"
		print Fore.WHITE+''+Back.BLACK

	print " "
	raw_input("Press Enter to exit ...")