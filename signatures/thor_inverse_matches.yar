/*
	THOR Yara Inverse Matches
	> Detect system file manipulations and common APT anomalies

	This is an extract from the THOR signature database

	Reference:
	http://www.bsk-consulting.de/2014/05/27/inverse-yara-signature-matching/
	https://www.bsk-consulting.de/2014/08/28/scan-system-files-manipulations-yara-inverse-matching-22/

	Notice: These rules require an external variable called "filename"
*/

private rule WINDOWS_UPDATE_BDC
{
condition:
    (uint32be(0) == 0x44434d01 and // magic: DCM PA30
     uint32be(4) == 0x50413330)
    or
    (uint32be(0) == 0x44434401 and
     uint32be(12)== 0x50413330)    // magic: DCD PA30
}  

/* Rules -------------------------------------------------------------------- */

rule iexplore_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal iexplore.exe - typical strings not found in file"
		date = "23/04/2014"
		score = 55
	strings:
		$win2003_win7_u1 = "IEXPLORE.EXE" wide nocase
		$win2003_win7_u2 = "Internet Explorer" wide fullword
		$win2003_win7_u3 = "translation" wide fullword nocase
		$win2003_win7_u4 = "varfileinfo" wide fullword nocase
	condition:
		filename == "iexplore.exe" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule svchost_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal svchost.exe - typical strings not found in file"
		date = "23/04/2014"
		score = 55
	strings:
		$win2003_win7_u1 = "svchost.exe" wide nocase
		$win2003_win7_u3 = "coinitializesecurityparam" wide fullword nocase
		$win2003_win7_u4 = "servicedllunloadonstop" wide fullword nocase
		$win2000 = "Generic Host Process for Win32 Services" wide fullword
		$win2012 = "Host Process for Windows Services" wide fullword
	condition:
		filename == "svchost.exe" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

/* removed 1 rule here */	

rule explorer_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal explorer.exe - typical strings not found in file"
		date = "27/05/2014"
		score = 55
	strings:
		$s1 = "EXPLORER.EXE" wide fullword
		$s2 = "Windows Explorer" wide fullword
	condition:
		filename == "explorer.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule sethc_ANOMALY {
	meta:
		description = "Sethc.exe has been replaced - Indicates Remote Access Hack RDP"
		author = "F. Roth"
		reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
		date = "2014/01/23"
		score = 70
	strings:
		$s1 = "stickykeys" fullword nocase
		$s2 = "stickykeys" wide nocase
		$s3 = "Control_RunDLL access.cpl" wide fullword
		$s4 = "SETHC.EXE" wide fullword
	condition:
		filename == "sethc.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule Utilman_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal utilman.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 70
	strings:
		$win7 = "utilman.exe" wide fullword
		$win2000 = "Start with Utility Manager" fullword wide
		$win2012 = "utilman2.exe" fullword wide		
	condition:
		filename == "utilman.exe" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule osk_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal osk.exe (On Screen Keyboard) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$s1 = "Accessibility On-Screen Keyboard" wide fullword
		$s2 = "\\oskmenu" wide fullword
		$s3 = "&About On-Screen Keyboard..." wide fullword
		$s4 = "Software\\Microsoft\\Osk" wide	
	condition:
		filename == "osk.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule magnify_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal magnify.exe (Magnifier) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "Microsoft Screen Magnifier" wide fullword
		$win2000 = "Microsoft Magnifier" wide fullword
		$winxp = "Software\\Microsoft\\Magnify" wide	
	condition:
		filename =="magnify.exe" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule narrator_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal narrator.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "Microsoft-Windows-Narrator" wide fullword
		$win2000 = "&About Narrator..." wide fullword
		$win2012 = "Screen Reader" wide fullword
		$winxp = "Software\\Microsoft\\Narrator"
		$winxp_en = "SOFTWARE\\Microsoft\\Speech\\Voices" wide	
	condition:
		filename == "narrator.exe" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule notepad_ANOMALY {
	meta:
		author = "Florian Roth"
		description = "Abnormal notepad.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "HELP_ENTRY_ID_NOTEPAD_HELP" wide fullword
		$win2000 = "Do you want to create a new file?" wide fullword
		$win2003 = "Do you want to save the changes?" wide 
		$winxp = "Software\\Microsoft\\Notepad" wide
		$winxp_de = "Software\\Microsoft\\Notepad" wide 
	condition:
		filename == "notepad.exe" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

/* NEW ---------------------------------------------------------------------- */

rule csrss_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file csrss.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "17542707a3d9fa13c569450fd978272ef7070a77"
	strings:
		$s1 = "Client Server Runtime Process" fullword wide
		$s4 = "name=\"Microsoft.Windows.CSRSS\"" fullword ascii
		$s5 = "CSRSRV.dll" fullword ascii
		$s6 = "CsrServerInitialization" fullword ascii
	condition:
		filename == "csrss.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule conhost_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file conhost.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "1bd846aa22b1d63a1f900f6d08d8bfa8082ae4db"
	strings:	
		$s2 = "Console Window Host" fullword wide
	condition:
		filename == "conhost.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule wininit_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file wininit.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "2de5c051c0d7d8bcc14b1ca46be8ab9756f29320"
	strings:	
		$s1 = "Windows Start-Up Application" fullword wide
	condition:
		filename == "wininit.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule winlogon_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file winlogon.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "af210c8748d77c2ff93966299d4cd49a8c722ef6"
	strings:		
		$s1 = "AuthzAccessCheck failed" fullword
		$s2 = "Windows Logon Application" fullword wide
	condition:
		filename == "winlogon.exe" and not 1 of ($s*) 
		and not WINDOWS_UPDATE_BDC
		and not filepath contains "Malwarebytes"
}

rule SndVol_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file SndVol.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "e057c90b675a6da19596b0ac458c25d7440b7869"
	strings:	
		$s1 = "Volume Control Applet" fullword wide
	condition:
		filename == "sndvol.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule doskey_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file doskey.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "f2d1995325df0f3ca6e7b11648aa368b7e8f1c7f"
	strings:		
		$s3 = "Keyboard History Utility" fullword wide
	condition:
		filename == "doskey.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule lsass_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file lsass.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "04abf92ac7571a25606edfd49dca1041c41bef21"
	strings:
		$s1 = "LSA Shell" fullword wide
		$s2 = "<description>Local Security Authority Process</description>" fullword ascii
		$s3 = "Local Security Authority Process" fullword wide
		$s4 = "LsapInitLsa" fullword
	condition:
		filename == "lsass.exe" and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule taskmgr_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file taskmgr.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/03/16"
		hash = "e8b4d84a28e5ea17272416ec45726964fdf25883"
	strings:		
		$s0 = "Windows Task Manager" fullword wide
		$s1 = "taskmgr.chm" fullword
		$s2 = "TmEndTaskHandler::" ascii
	condition:
		( filename == "taskmgr.exe" or filename == "Taskmgr.exe" ) and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

/* removed 22 rules here */

/* APT ---------------------------------------------------------------------- */

rule APT_Cloaked_PsExec
	{
	meta:
		description = "Looks like a cloaked PsExec. May be APT group activity."
		date = "2014-07-18"
		author = "Florian Roth"
		score = 60
	strings:
		$s0 = "psexesvc.exe" wide fullword
		$s1 = "Sysinternals PsExec" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 
		and not filename matches /^(psexec.exe|psexesvc.exe)$/is
}

/* removed 6 rules here */	

rule APT_Cloaked_SuperScan
	{
	meta:
		description = "Looks like a cloaked SuperScan Port Scanner. May be APT group activity."
		date = "2014-07-18"
		author = "Florian Roth"
		score = 50
	strings:
		$magic = { 4d 5a }
		$s0 = "SuperScan4.exe" wide fullword
		$s1 = "Foundstone Inc." wide fullword
	condition:
		( $magic at 0 ) and $s0 and $s1 and not filename contains "superscan"
}

rule APT_Cloaked_ScanLine
	{
	meta:
		description = "Looks like a cloaked ScanLine Port Scanner. May be APT group activity."
		date = "2014-07-18"
		author = "Florian Roth"
		score = 50
	strings:
		$magic = { 4d 5a }
		$s0 = "ScanLine" wide fullword
		$s1 = "Command line port scanner" wide fullword
		$s2 = "sl.exe" wide fullword
	condition:
		( $magic at 0 ) and $s0 and $s1 and $s2 and not filename == "sl.exe"
}

rule SAM_Hive_Backup
{
	meta:
		description = "Detects a SAM hive backup file"
		author = "Florian Roth"
		reference = "https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump"
		score = 60
		date = "2015/03/31"
	strings: 
		$s1 = "\\SystemRoot\\System32\\Config\\SAM" wide fullword
	condition:
		uint32(0) == 0x66676572 and $s1 in (0..100) and
			not filename contains "sam.log" and
			not filename contains "_sam" and 
			not filename == "SAM" and
			not filename == "sam"
}
