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
# v0.3.2
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
import platform
import psutil
from colorama import Fore, Back, Style
from colorama import init


def scanPath(path, rule_sets, filename_iocs, filename_suspicious_iocs, hashes, false_hashes):
	
	# Startup
	log("INFO","Scanning %s ...  " % path)

	# Counter
	c = 0

	# Get application path
	appPath = getApplicationPath()

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

					# Skip program directory
					if appPath in filePath:
						log("DEBUG", "Skipping file in program directory FILE: %s" % filePath)
						continue

					file_size = os.stat(filePath).st_size
					# print file_size

					# File Name Checks -------------------------------------------------
					for regex in filename_iocs.keys():
						match = re.search(r'%s' % regex, filePath)
						if match:
							description = filename_iocs[regex]
							log("ALERT", "File Name IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, filePath))

					# File Name Suspicious Checks --------------------------------------
					for regex in filename_suspicious_iocs.keys():
						match = re.search(r'%s' % regex, filePath)
						if match:
							description = filename_suspicious_iocs[regex]
							log("WARNING", "File Name Suspicious IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, filePath))

					# Hash Check -------------------------------------------------------
					if file_size > ( args.s * 1024):
						continue

					# Read file complete
					with open(filePath, 'rb') as f:
						fileData = f.read()

					md5, sha1, sha256 = generateHashes(fileData)

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

					# Yara Check -------------------------------------------------------
					try:
						for rules in rule_sets:
							matches = rules.match(data=fileData)
							if matches:
								for match in matches:
									log("ALERT", "Yara Rule MATCH: %s FILE: %s" % ( match.rule, filePath))
					except Exception, e:
						if args.debug:
							traceback.print_exc()

				except Exception, e:
					if args.debug:
						traceback.print_exc()


def scanProcesses(rule_sets, filename_iocs, filename_suspicious_iocs):
	# WMI Handler
	c = wmi.WMI()
	processes = c.Win32_Process()
	t_systemroot = os.environ['SYSTEMROOT']

	# WinInit PID
	wininit_pid = 0
	# LSASS Counter
	lsass_count = 0

	for process in processes:

		try:
			
			# Gather Process Information --------------------------------------
			pid = process.ProcessId
			name = process.Name
			cmd = process.CommandLine
			if not cmd:
				cmd = "N/A"
			if not name:
				name = "N/A"			
			path = "none"
			parent_pid = process.ParentProcessId
			priority = process.Priority
			ws_size = process.VirtualSize
			if process.ExecutablePath:
				path = process.ExecutablePath
			# Owner
			try:
				owner_raw = process.GetOwner()
				owner = owner_raw[2]
			except Exception, e:
				owner = "unknown"			

		except Exception, e:
			log("ALERT", "Error getting all process information. Did you run the scanner 'As Administrator'?")
			continue

		# Is parent to other processes - save PID
		if name == "wininit.exe":
			wininit_pid = pid

		# Skip some PIDs ------------------------------------------------------
		if pid == 0 or pid == 4:
			log("INFO", "Skipping Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))
			continue

		# Skip own process ----------------------------------------------------
		if os.getpid() == pid:
			log("INFO", "Skipping LOKI Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))
			continue

		# Print info ----------------------------------------------------------
		log("NOTICE", "Scanning Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))

		# Special Checks ------------------------------------------------------
		# better executable path
		if not "\\" in cmd and path != "none":
			cmd = path

		# Skeleton Key Malware Process
		if re.search(r'psexec .* [a-fA-F0-9]{32}', cmd, re.IGNORECASE):
			log("WARNING", "Process that looks liks SKELETON KEY psexec execution detected PID: %s NAME: %s CMD: %s" % ( pid, name, cmd))

		# File Name Checks -------------------------------------------------
		for regex in filename_iocs.keys():
			match = re.search(r'%s' % regex, cmd)
			if match:
				description = filename_iocs[regex]
				log("ALERT", "File Name IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, cmd))

		# File Name Suspicious Checks --------------------------------------
		for regex in filename_suspicious_iocs.keys():
			match = re.search(r'%s' % regex, cmd)
			if match:
				description = filename_suspicious_iocs[regex]
				log("WARNING", "File Name Suspicious IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, cmd))

		# Yara rule match
		# only on processes with a small working set size
		if int(ws_size) < ( 100 * 1048576 ): # 100 MB
			try:
				alerts = []
				for rules in rule_sets:
					matches = rules.match(pid=pid)
					if matches:
						for match in matches:
							# print match.rule
							alerts.append("Yara Rule MATCH: %s PID: %s NAME: %s CMD: %s" % ( match.rule, pid, name, cmd))
				if len(alerts) > 3:
					log("INFO", "Too many matches on process memory - most likely a false positive PID: %s NAME: %s CMD: %s" % (pid, name, cmd))
				elif len(alerts) > 0:
					for alert in alerts:
						log("ALERT", alert)
			except Exception, e:
				log("ERROR", "Error while process memory Yara check (maybe the process doesn't exist anymore or access denied). PID: %s NAME: %s" % ( pid, name))
		else:
			log("DEBUG", "Skipped Yara memory check due to the process' big working set size (stability issues) PID: %s NAME: %s SIZE: %s" % ( pid, name, ws_size))
						
		###############################################################
		# THOR Process Anomaly Checks
		# Source: Sysforensics http://goo.gl/P99QZQ

		# Process: System
		if name == "System" and not pid == 4:
			log("WARNING", "System process without PID=4 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))

		# Process: smss.exe
		if name == "smss.exe" and not parent_pid == 4:
			log("WARNING", "smss.exe parent PID is != 4 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if path != "none":
			if name == "smss.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "smss.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "smss.exe" and priority is not 11:
			log("WARNING", "smss.exe priority is not 11 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))

		# Process: csrss.exe
		if path != "none":
			if name == "csrss.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "csrss.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "csrss.exe" and priority is not 13:
			log("WARNING", "csrss.exe priority is not 13 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))

		# Process: wininit.exe
		if path != "none":
			if name == "wininit.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "wininit.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "wininit.exe" and priority is not 13:
			log("NOTICE", "wininit.exe priority is not 13 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		# Is parent to other processes - save PID
		if name == "wininit.exe":
			wininit_pid = pid

		# Process: services.exe
		if path != "none":
			if name == "services.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "services.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "services.exe" and priority is not 9:
			log("WARNING", "services.exe priority is not 9 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if wininit_pid > 0:
			if name == "services.exe" and not parent_pid == wininit_pid:
				log("WARNING", "services.exe parent PID is not the one of wininit.exe PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))

		# Process: lsass.exe
		if path != "none":
			if name == "lsass.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "lsass.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "lsass.exe" and priority is not 9:
			log("WARNING", "lsass.exe priority is not 9 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if wininit_pid > 0:
			if name == "lsass.exe" and not parent_pid == wininit_pid:
				log("WARNING", "lsass.exe parent PID is not the one of wininit.exe PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		# Only a single lsass process is valid - count occurrences
		if name == "lsass.exe":
			lsass_count += 1
			if lsass_count > 1:
				log("WARNING", "lsass.exe count is higher than 1 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))

		# Process: svchost.exe
		if path is not "none":
			if name == "svchost.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "svchost.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "svchost.exe" and priority is not 8:
			log("NOTICE", "svchost.exe priority is not 8 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if name == "svchost.exe" and not ( owner.upper().startswith("NT ") or owner.upper().startswith("NET") or owner.upper().startswith("LO") or owner.upper().startswith("SYSTEM") ):
			log("WARNING", "svchost.exe process owner is suspicious PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))

		if name == "svchost.exe" and not " -k " in cmd and cmd != "N/A":
			print cmd
			log("WARNING", "svchost.exe process does not contain a -k in its command line PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))

		# Process: lsm.exe
		if path != "none":
			if name == "lsm.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
				log("WARNING", "lsm.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "lsm.exe" and priority is not 8:
			log("NOTICE", "lsm.exe priority is not 8 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if name == "lsm.exe" and not ( owner.startswith("NT ") or owner.startswith("LO") or owner.startswith("SYSTEM") ):
			log("WARNING", "lsm.exe process owner is suspicious PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if wininit_pid > 0:
			if name == "lsm.exe" and not parent_pid == wininit_pid:
				log("WARNING", "lsm.exe parent PID is not the one of wininit.exe PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))

		# Process: winlogon.exe
		if name == "winlogon.exe" and priority is not 13:
			log("WARNING", "winlogon.exe priority is not 13 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
				str(pid), name, owner, cmd, path))
		if re.search("(Windows 7|Windows Vista)", getPlatformFull()):
			if name == "winlogon.exe" and parent_pid > 0:
				for proc in processes:
					if parent_pid == proc.ProcessId:
						log("WARNING", "winlogon.exe has a parent ID but should have none PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s PARENTPID: %s" % (
							str(pid), name, owner, cmd, path, str(parent_pid)))

		# Process: explorer.exe
		if path != "none":
			if name == "explorer.exe" and not t_systemroot.lower() in path.lower():
				log("WARNING", "explorer.exe path is not %%SYSTEMROOT%% PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
					str(pid), name, owner, cmd, path))
		if name == "explorer.exe" and parent_pid > 0:
			for proc in processes:
				if parent_pid == proc.ProcessId:
					log("NOTICE", "explorer.exe has a parent ID but should have none PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
						str(pid), name, owner, cmd, path))


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


def setNice():
	try:
		pid = os.getpid()
		p = psutil.Process(pid)
		log("INFO", "Setting LOKI process with PID: %s to priority IDLE" % pid)
		p.set_nice(psutil.IDLE_PRIORITY_CLASS)
		return 1
	except Exception, e:
		log("ERROR", "Error setting nice value of THOR process")
		return 0


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


def initializeYaraRules():

	yaraRules = []

	try:
		for file in ( os.listdir(os.path.join(getApplicationPath(), "./signatures"))  ):
			try:

				# Skip hidden, backup or system related files
				if file.startswith(".") or file.startswith("~") or file.startswith("_"):
					continue

				# Extension
				extension = os.path.splitext(file)[1].lower()

				# Full Path
				yaraRuleFile = os.path.join(getApplicationPath(), "./signatures/%s" % file)

				# Encrypted
				if extension == ".yar":
					try:
						compiledRules = yara.compile(yaraRuleFile)
						yaraRules.append(compiledRules)
						log("INFO", "Successfully compiled Yara rules from file %s" % file)
					except Exception, e:
						log("ERROR", "Error in plain text Yara file: %s" % file)
						if args.debug:
							traceback.print_exc()

			except Exception, e:
				log("ERROR", "Error reading signature file /signatures/%s ERROR: %s" % file)
				if args.debug:
					traceback.print_exc()

	except Exception, e:
		log("ERROR", "Error reading signature folder /signatures/")
		if args.debug:
			traceback.print_exc()

	return yaraRules


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


def getApplicationPath():
	try:
		application_path = ""
		if getattr(sys, 'frozen', False):
			application_path = os.path.dirname(sys.executable)
		elif __file__:
			application_path = os.path.dirname(__file__)
		if application_path != "":
			# Working directory change skipped due to the function to create TXT, CSV and HTML file on the local file
			# system when thor is started from a read only network share
			# os.chdir(application_path)
			pass
		if application_path == "":
			application_path = os.path.dirname(os.path.realpath(__file__))
		return application_path
	except Exception, e:
		log("ERROR","Error while evaluation of application path")


def log(mes_type, message):

	global alerts, warnings

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
			alerts += 1
		if mes_type == "DEBUG":
			if not args.debug:
				return
			color = Fore.WHITE
		if mes_type == "WARNING":
			color = Fore.YELLOW
			warnings += 1
		if mes_type == "NOTICE":
			color = Fore.CYAN
		if mes_type == "RESULT":
			if "clean" in message.lower():
				color = Fore.BLACK+Back.GREEN
			elif "suspicious" in message.lower():
				color = Fore.BLACK+Back.YELLOW
			else:
				color = Fore.BLACK+Back.RED

		# Print to console
		if mes_type == "RESULT":
			res_message = "\b\b[%s] %s" % (mes_type, removeNonAsciiDrop(message))
			print color,res_message,Back.BLACK
			print Fore.WHITE,Style.NORMAL
		else:
			print color,"\b\b[%s] %s" % (mes_type, removeNonAsciiDrop(message)),Back.BLACK,Fore.WHITE,Style.NORMAL

		# Write to file
		with open(args.l, "a") as logfile:
			logfile.write("%s %s LOKI: %s\n" % (getSyslogTimestamp(), t_hostname, removeNonAsciiDrop(message)))

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
	print Back.GREEN + " ".ljust(79) + Back.BLACK
	print "  "
	print "   " + Back.GREEN + "  " + Back.BLACK + "      " + Back.GREEN + "      " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK
	print "   " + Back.GREEN + "  " + Back.BLACK + "      " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "    " + Back.BLACK + "    " + Back.GREEN + "  " + Back.BLACK
	print "   " + Back.GREEN + "      " + Back.BLACK + "  " + Back.GREEN + "      " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK + "  " + Back.GREEN + "  " + Back.BLACK
	print "  "
	print "  Simple IOC Scanner"
	print "  "
	print "  (C) Florian Roth - BSK Consulting GmbH"
	print "  Jan 2015"
	print "  Version 0.3.2"
	print "  "
	print "  DISCLAIMER - USE AT YOUR OWN RISK"
	print "  "
	print Back.GREEN + " ".ljust(79) + Back.BLACK
	print Fore.WHITE+''+Back.BLACK


# MAIN ################################################################
if __name__ == '__main__':

	# Counters --------------------------------------------------------
	warnings = 0
	alerts = 0

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

	# Set process to nice priority ------------------------------------
	setNice()

	# Read IOCs -------------------------------------------------------
	# File Name IOCs
	filenameIOCs = getFileNameIOCs(os.path.join(getApplicationPath(), "./signatures/filename-iocs.txt"))
	log("INFO","File Name Characteristics initialized with %s regex patterns" % len(filenameIOCs.keys()))
	# File Name Suspicious IOCs
	filenameSuspiciousIOCs = getFileNameIOCs(os.path.join(getApplicationPath(), "./signatures/filename-suspicious.txt"))
	log("INFO","File Name Suspicious Characteristics initialized with %s regex patterns" % len(filenameSuspiciousIOCs.keys()))
	# Hash based IOCs
	fileHashes = getHashes(os.path.join(getApplicationPath(), "./signatures/hash-iocs.txt"))
	log("INFO","Malware Hashes initialized with %s hashes" % len(fileHashes.keys()))
	# Hash based False Positives
	falseHashes = getHashes(os.path.join(getApplicationPath(), "./signatures/falsepositive-hashes.txt"))
	log("INFO","False Positive Hashes initialized with %s hashes" % len(falseHashes.keys()))
	# Compile Yara Rules
	yaraRules = initializeYaraRules()

	# Scan Processes --------------------------------------------------
	resultProc = False
	if not args.noprocscan:
		scanProcesses(yaraRules, filenameIOCs, filenameSuspiciousIOCs)

	# Scan Path -------------------------------------------------------
	resultFS = False
	if not args.nofilescan:
		scanPath(args.p, yaraRules, filenameIOCs, filenameSuspiciousIOCs, fileHashes, falseHashes)

	# Result ----------------------------------------------------------
	print " "
	if alerts:
		log("RESULT", "INDICATORS DETECTED!")
		log("RESULT", "Loki recommends a forensic analysis and triage with a professional triage tool like THOR APT Scanner.")
	elif warnings:
		log("RESULT", "SUSPICIOUS OBJECTS DETECTED!")
		log("RESULT", "Loki recommends a deeper analysis of the suspicious objects.")
	else:
		log("RESULT", "SYSTEM SEEMS TO BE CLEAN.")

	print " "
	if not args.dontwait:
		raw_input("Press Enter to exit ...")