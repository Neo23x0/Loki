/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2015-06-02
	Identifier: APT28
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT28_CHOPSTICK {
	meta:
		description = "Detects a malware that behaves like CHOPSTICK mentioned in APT28 report"
		author = "Florian Roth"
		reference = "https://goo.gl/v3ebal"
		date = "2015-06-02"
		hash = "f4db2e0881f83f6a2387ecf446fcb4a4c9f99808"
		score = 60
	strings:
		$s0 = "jhuhugit.tmp" fullword ascii /* score: '14.005' */
		$s8 = "KERNEL32.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 14405 times */
		$s9 = "IsDebuggerPresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3518 times */
		$s10 = "IsProcessorFeaturePresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 1383 times */
		$s11 = "TerminateProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 13081 times */
		$s13 = "DeleteFileA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 1384 times */
		$s15 = "GetProcessHeap" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 5875 times */
		$s16 = "!This program cannot be run in DOS mode." fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 20908 times */
		$s17 = "LoadLibraryA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 5461 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 722KB and all of them
}

rule APT28_SourFace_Malware1 {
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		hash1 = "e2450dffa675c61aa43077b25b12851a910eeeb6"
		hash2 = "d9c53adce8c35ec3b1e015ec8011078902e6800b"
		score = 60
	strings:
		$s0 = "coreshell.dll" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "Core Shell Runtime Service" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "\\chkdbg.log" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule APT28_SourFace_Malware2 {
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		super_rule = 1
		hash0 = "367d40465fd1633c435b966fa9b289188aa444bc"
		hash1 = "cf3220c867b81949d1ce2b36446642de7894c6dc"
		hash2 = "ed48ef531d96e8c7360701da1c57e2ff13f12405"
		hash3 = "682e49efa6d2549147a21993d64291bfa40d815a"
		hash4 = "a8551397e1f1a2c0148e6eadcb56fa35ee6009ca"
		hash5 = "f5b3e98c6b5d65807da66d50bd5730d35692174d"
		score = 60
	strings:
		$s0 = "coreshell.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "Applicate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule APT28_SourFace_Malware3 {
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		super_rule = 1
		hash0 = "85522190958c82589fa290c0835805f3d9a2f8d6"
		hash1 = "d9c53adce8c35ec3b1e015ec8011078902e6800b"
		hash2 = "367d40465fd1633c435b966fa9b289188aa444bc"
		hash3 = "d87b310aa81ae6254fff27b7d57f76035f544073"
		hash4 = "cf3220c867b81949d1ce2b36446642de7894c6dc"
		hash5 = "ed48ef531d96e8c7360701da1c57e2ff13f12405"
		hash6 = "682e49efa6d2549147a21993d64291bfa40d815a"
		hash7 = "a8551397e1f1a2c0148e6eadcb56fa35ee6009ca"
		hash8 = "f5b3e98c6b5d65807da66d50bd5730d35692174d"
		hash9 = "e2450dffa675c61aa43077b25b12851a910eeeb6"
		score = 60
	strings:
		$s0 = "coreshell.dll" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "Core Shell Runtime Service" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

