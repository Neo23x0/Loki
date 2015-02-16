
/* import "pe" - memory leak */

/* FIVE EYES ------------------------------------------------------------------------------- */

rule FiveEyes_QUERTY_Malwareqwerty_20121 {
	meta:
		description = "FiveEyes QUERTY Malware - file 20121.xml"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "8263fb58350f3b1d3c4220a602421232d5e40726"
	strings:
		$s0 = "<configFileName>20121_cmdDef.xml</configFileName>" fullword ascii
		$s1 = "<name>20121.dll</name>" fullword ascii
		$s2 = "<codebase>\"Reserved for future use.\"</codebase>" fullword ascii
		$s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
		$s4 = "<platform type=\"1\">" fullword ascii
		$s5 = "</plugin>" fullword ascii
		$s6 = "</pluginConfig>" fullword ascii
		$s7 = "<pluginConfig>" fullword ascii
		$s8 = "</platform>" fullword ascii
		$s9 = "</lpConfig>" fullword ascii
		$s10 = "<lpConfig>" fullword ascii
	condition:
		9 of them
}

rule FiveEyes_QUERTY_Malwaresig_20123_sys {
	meta:
		description = "FiveEyes QUERTY Malware - file 20123.sys.bin"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "a0f0087bd1f8234d5e847363d7e15be8a3e6f099"
	strings:
		$s0 = "20123.dll" fullword ascii
		$s1 = "kbdclass.sys" fullword wide
		$s2 = "IoFreeMdl" fullword ascii
		$s3 = "ntoskrnl.exe" fullword ascii
		$s4 = "KfReleaseSpinLock" fullword ascii
	condition:
		all of them
}

rule FiveEyes_QUERTY_Malwaresig_20123_cmdDef {
	meta:
		description = "FiveEyes QUERTY Malware - file 20123_cmdDef.xml"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "7b08fc77629f6caaf8cc4bb5f91be6b53e19a3cd"
	strings:
		$s0 = "<shortDescription>Keystroke Collector</shortDescription>" fullword ascii
		$s1 = "This plugin is the E_Qwerty Kernel Mode driver for logging keys.</description>" fullword ascii
		$s2 = "<commands/>" fullword ascii
		$s3 = "</version>" fullword ascii
		$s4 = "<associatedImplantId>20121</associatedImplantId>" fullword ascii
		$s5 = "<rightsRequired>System or Administrator (if Administrator, I think the DriverIns" ascii
		$s6 = "<platforms>Windows NT, Windows 2000, Windows XP (32/64 bit), Windows 2003 (32/64" ascii
		$s7 = "<projectpath>plugin/Collection</projectpath>" fullword ascii
		$s8 = "<dllDepend>None</dllDepend>" fullword ascii
		$s9 = "<minorType>0</minorType>" fullword ascii
		$s10 = "<pluginname>E_QwertyKM</pluginname>" fullword ascii
		$s11 = "</comments>" fullword ascii
		$s12 = "<comments>" fullword ascii
		$s13 = "<majorType>1</majorType>" fullword ascii
		$s14 = "<files>None</files>" fullword ascii
		$s15 = "<poc>Erebus</poc>" fullword ascii
		$s16 = "</plugin>" fullword ascii
		$s17 = "<team>None</team>" fullword ascii
		$s18 = "<?xml-stylesheet type=\"text/xsl\" href=\"../XSLT/pluginHTML.xsl\"?>" fullword ascii
		$s19 = "<pluginsDepend>U_HookManager v1.0, Kernel Covert Store v1.0</pluginsDepend>" fullword ascii
		$s20 = "<plugin id=\"20123\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi" ascii
	condition:
		14 of them
}

rule FiveEyes_QUERTY_Malwaresig_20121_dll {
	meta:
		description = "FiveEyes QUERTY Malware - file 20121.dll.bin"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "89504d91c5539a366e153894c1bc17277116342b"
	strings:
		$s0 = "WarriorPride\\production2.0\\package\\E_Wzowski" ascii
		$s1 = "20121.dll" fullword ascii
	condition:
		all of them
}
rule FiveEyes_QUERTY_Malwareqwerty_20123 {
	meta:
		description = "FiveEyes QUERTY Malware - file 20123.xml"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "edc7228b2e27df9e7ff9286bddbf4e46adb51ed9"
	strings:
		$s0 = "<!-- edited with XMLSPY v5 rel. 4 U (http://www.xmlspy.com) by TEAM (RENEGADE) -" ascii
		$s1 = "<configFileName>20123_cmdDef.xml</configFileName>" fullword ascii
		$s2 = "<name>20123.sys</name>" fullword ascii
		$s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
		$s4 = "<codebase>/bin/i686-pc-win32/debug</codebase>" fullword ascii
		$s5 = "<platform type=\"1\">" fullword ascii
		$s6 = "</plugin>" fullword ascii
		$s7 = "</pluginConfig>" fullword ascii
		$s8 = "<pluginConfig>" fullword ascii
		$s9 = "</platform>" fullword ascii
		$s10 = "</lpConfig>" fullword ascii
		$s11 = "<lpConfig>" fullword ascii
	condition:
		9 of them
}

rule FiveEyes_QUERTY_Malwaresig_20120_dll {
	meta:
		description = "FiveEyes QUERTY Malware - file 20120.dll.bin"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "6811bfa3b8cda5147440918f83c40237183dbd25"
	strings:
		$s0 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.txt" fullword wide
		$s1 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.xml" fullword wide
		$s2 = "Failed to send the EQwerty_driverStatusCommand to the implant." fullword ascii
		$s3 = "- Log Used (number of windows) - %d" fullword wide
		$s4 = "- Log Limit (number of windows) - %d" fullword wide
		$s5 = "Process or User Default Language" fullword wide
		$s6 = "Windows 98/Me, Windows NT 4.0 and later: Vietnamese" fullword wide
		$s7 = "- Logging of keystrokes is switched ON" fullword wide
		$s8 = "- Logging of keystrokes is switched OFF" fullword wide
		$s9 = "Qwerty is currently logging active windows with titles containing the fo" wide
		$s10 = "Windows 95, Windows NT 4.0 only: Korean (Johab)" fullword wide
		$s11 = "FAILED to get Qwerty Status" fullword wide
		$s12 = "- Successfully retrieved Log from Implant." fullword wide
		$s13 = "- Logging of all Windows is toggled ON" fullword wide
		$s14 = "- Logging of all Windows is toggled OFF" fullword wide
		$s15 = "Qwerty FAILED to retrieve window list." fullword wide
		$s16 = "- UNSUCCESSFUL Log Retrieval from Implant." fullword wide
		$s17 = "The implant failed to return a valid status" fullword ascii
		$s18 = "- Log files were NOT generated!" fullword wide
		$s19 = "Windows 2000/XP: Armenian. This is Unicode only." fullword wide
		$s20 = "- This machine is using a PS/2 Keyboard - Continue on using QWERTY" fullword wide
	condition:
		10 of them
}

rule FiveEyes_QUERTY_Malwaresig_20120_cmdDef {
	meta:
		description = "FiveEyes QUERTY Malware - file 20120_cmdDef.xml"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "cda9ceaf0a39d6b8211ce96307302a53dfbd71ea"
	strings:
		$s0 = "This PPC gets the current keystroke log." fullword ascii
		$s1 = "This command will add the given WindowTitle to the list of Windows to log keys f" ascii
		$s2 = "This command will remove the WindowTitle corresponding to the given window title" ascii
		$s3 = "This command will return the current status of the Keyboard Logger (Whether it i" ascii
		$s4 = "This command Toggles logging of all Keys. If allkeys is toggled all keystrokes w" ascii
		$s5 = "<definition>Turn logging of all keys on|off</definition>" fullword ascii
		$s6 = "<name>Get Keystroke Log</name>" fullword ascii
		$s7 = "<description>Keystroke Logger Lp Plugin</description>" fullword ascii
		$s8 = "<definition>display help for this function</definition>" fullword ascii
		$s9 = "This command will switch ON Logging of keys. All keys taht are entered to a acti" ascii
		$s10 = "Set the log limit (in number of windows)" fullword ascii
		$s11 = "<example>qwgetlog</example>" fullword ascii
		$s12 = "<aliasName>qwgetlog</aliasName>" fullword ascii
		$s13 = "<definition>The title of the Window whose keys you wish to Log once it becomes a" ascii
		$s14 = "This command will switch OFF Logging of keys. No keystrokes will be captured" fullword ascii
		$s15 = "<definition>The title of the Window whose keys you no longer whish to log</defin" ascii
		$s16 = "<command id=\"32\">" fullword ascii
		$s17 = "<command id=\"3\">" fullword ascii
		$s18 = "<command id=\"7\">" fullword ascii
		$s19 = "<command id=\"1\">" fullword ascii
		$s20 = "<command id=\"4\">" fullword ascii
	condition:
		10 of them
}

rule FiveEyes_QUERTY_Malwareqwerty_20120 {
	meta:
		description = "FiveEyes QUERTY Malware - file 20120.xml"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "597082f05bfd3225587d480c30f54a7a1326a892"
	strings:
		$s0 = "<configFileName>20120_cmdDef.xml</configFileName>" fullword ascii
		$s1 = "<name>20120.dll</name>" fullword ascii
		$s2 = "<codebase>\"Reserved for future use.\"</codebase>" fullword ascii
		$s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
		$s4 = "<platform type=\"1\">" fullword ascii
		$s5 = "</plugin>" fullword ascii
		$s6 = "</pluginConfig>" fullword ascii
		$s7 = "<pluginConfig>" fullword ascii
		$s8 = "</platform>" fullword ascii
		$s9 = "</lpConfig>" fullword ascii
		$s10 = "<lpConfig>" fullword ascii
	condition:
		all of them
}

rule FiveEyes_QUERTY_Malwaresig_20121_cmdDef {
	meta:
		description = "FiveEyes QUERTY Malware - file 20121_cmdDef.xml"
		author = "Florian Roth"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "64ac06aa4e8d93ea6063eade7ce9687b1d035907"
	strings:
		$s0 = "<shortDescription>Keystroke Logger Plugin.</shortDescription>" fullword ascii
		$s1 = "<message>Failed to get File Time</message>" fullword ascii
		$s2 = "<description>Keystroke Logger Plugin.</description>" fullword ascii
		$s3 = "<message>Failed to set File Time</message>" fullword ascii
		$s4 = "</commands>" fullword ascii
		$s5 = "<commands>" fullword ascii
		$s6 = "</version>" fullword ascii
		$s7 = "<associatedImplantId>20120</associatedImplantId>" fullword ascii
		$s8 = "<message>No Comms. with Driver</message>" fullword ascii
		$s9 = "</error>" fullword ascii
		$s10 = "<message>Invalid File Size</message>" fullword ascii
		$s11 = "<platforms>Windows (User/Win32)</platforms>" fullword ascii
		$s12 = "<message>File Size Mismatch</message>" fullword ascii
		$s13 = "<projectpath>plugin/Utility</projectpath>" fullword ascii
		$s14 = "<pluginsDepend>None</pluginsDepend>" fullword ascii
		$s15 = "<dllDepend>None</dllDepend>" fullword ascii
		$s16 = "<pluginname>E_QwertyIM</pluginname>" fullword ascii
		$s17 = "<rightsRequired>None</rightsRequired>" fullword ascii
		$s18 = "<minorType>0</minorType>" fullword ascii
		$s19 = "<code>00001002</code>" fullword ascii
		$s20 = "<code>00001001</code>" fullword ascii
	condition:
		12 of them
}


/* SKELETON KEY ---------------------------------------------------------------------------- */

rule skeleton_key_patcher
{
	meta:
		description = "Skeleton Key Patcher from Dell SecureWorks Report http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
	strings:
		$target_process = "lsass.exe" wide
		$dll1 = "cryptdll.dll"
		$dll2 = "samsrv.dll"

		$name = "HookDC.dll"

		$patched1 = "CDLocateCSystem"
		$patched2 = "SamIRetrievePrimaryCredentials"
		$patched3 = "SamIRetrieveMultiplePrimaryCredentials"
	condition:
		all of them
}

rule skeleton_key_injected_code
{
	meta:
		description = "Skeleton Key injected Code http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
	strings:
		$injected = { 33 C0 85 C9 0F 95 C0 48 8B 8C 24 40 01 00 00 48 33 CC E8 4D 02 00 
		00 48 81 C4 58 01 00 00 C3 }

		$patch_CDLocateCSystem = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B FA 
		8B F1 E8 ?? ?? ?? ?? 48 8B D7 8B CE 48 8B D8 FF 50 10 44 8B D8 85 C0 0F 88 A5 00 
		00 00 48 85 FF 0F 84 9C 00 00 00 83 FE 17 0F 85 93 00 00 00 48 8B 07 48 85 C0 0F 
		84 84 00 00 00 48 83 BB 48 01 00 00 00 75 73 48 89 83 48 01 00 00 33 D2 }

		$patch_SamIRetrievePrimaryCredential = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 
		24 18 57 48 83 EC 20 49 8B F9 49 8B F0 48 8B DA 48 8B E9 48 85 D2 74 2A 48 8B 42 
		08 48 85 C0 74 21 66 83 3A 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 66 83 
		78 1E 4B 75 07 B8 A1 02 00 C0 EB 14 E8 ?? ?? ?? ?? 4C 8B CF 4C 8B C6 48 8B D3 48 
		8B CD FF 50 18 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }

		$patch_SamIRetrieveMultiplePrimaryCredential  = { 48 89 5C 24 08 48 89 6C 24 10 
		48 89 74 24 18 57 48 83 EC 20 41 8B F9 49 8B D8 8B F2 8B E9 4D 85 C0 74 2B 49 8B 
		40 08 48 85 C0 74 22 66 41 83 38 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 
		66 83 78 1E 4B 75 07 B8 A1 02 00 C0 EB 12 E8 ?? ?? ?? ?? 44 8B CF 4C 8B C3 8B D6 
		8B CD FF 50 20 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }

	condition:
		any of them
}

/* REGIN ---------------------------------------------------------------------------------- */

rule Regin_APT_KernelDriver_Generic_A {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "187044596bc1328efa0ed636d8aa4a5c"
		hash2 = "06665b96e293b23acc80451abb413e50"
		hash3 = "d240f06e98c8d3e647cbf4d442d79475"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		
		$s0 = "atapi.sys" fullword wide
		$s1 = "disk.sys" fullword wide
		$s3 = "h.data" fullword ascii
		$s4 = "\\system32" fullword ascii
		$s5 = "\\SystemRoot" fullword ascii
		$s6 = "system" fullword ascii
		$s7 = "temp" fullword ascii
		$s8 = "windows" fullword ascii

		$x1 = "LRich6" fullword ascii
		$x2 = "KeServiceDescriptorTable" fullword ascii		
	condition:
		$m0 at 0 and $m1 and  	
		all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "ffb0b9b5b610191051a7bdf0806e1e47"
		hash2 = "bfbe8c3ee78750c3a520480700e440f8"
		hash3 = "b29ca4f22ae7b7b25f79c1d4a421139d"
		hash4 = "06665b96e293b23acc80451abb413e50"
		hash5 = "2c8b9d2885543d7ade3cae98225e263b"
		hash6 = "4b6b86c7fec1c574706cecedf44abded"
		hash7 = "187044596bc1328efa0ed636d8aa4a5c"
		hash8 = "d240f06e98c8d3e647cbf4d442d79475"
		hash9 = "6662c390b2bbbd291ec7987388fc75d7"
		hash10 = "1c024e599ac055312a4ab75b3950040a"
		hash11 = "ba7bb65634ce1e30c1e5415be3d1db1d"
		hash12 = "b505d65721bb2453d5039a389113b566"
		hash13 = "b269894f434657db2b15949641a67532"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s2 = "H.data" fullword ascii nocase
		$s3 = "INIT" fullword ascii
		$s4 = "ntoskrnl.exe" fullword ascii
		
		$v1 = "\\system32" fullword ascii
		$v2 = "\\SystemRoot" fullword ascii
		$v3 = "KeServiceDescriptorTable" fullword ascii	
		
		$w1 = "\\system32" fullword ascii
		$w2 = "\\SystemRoot" fullword ascii		
		$w3 = "LRich6" fullword ascii
		
		$x1 = "_snprintf" fullword ascii
		$x2 = "_except_handler3" fullword ascii
		
		$y1 = "mbstowcs" fullword ascii
		$y2 = "wcstombs" fullword ascii
		$y3 = "KeGetCurrentIrql" fullword ascii
		
		$z1 = "wcscpy" fullword ascii
		$z2 = "ZwCreateFile" fullword ascii
		$z3 = "ZwQueryInformationFile" fullword ascii
		$z4 = "wcslen" fullword ascii
		$z5 = "atoi" fullword ascii
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) ) 
		and filesize < 20KB
}

rule Regin_APT_KernelDriver_Generic_C {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "e0895336617e0b45b312383814ec6783556d7635"
		hash2 = "732298fa025ed48179a3a2555b45be96f7079712"		
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
	
		$s0 = "KeGetCurrentIrql" fullword ascii
		$s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		$s2 = "usbclass" fullword wide
		
		$x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
		$x2 = "Universal Serial Bus Class Driver" fullword wide
		$x3 = "5.2.3790.0" fullword wide
		
		$y1 = "LSA Shell" fullword wide
		$y2 = "0Richw" fullword ascii		
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($x*) or all of ($y*) ) 
		and filesize < 20KB
}

/* Update 27.11.14 */

rule Regin_sig_svcsstat {
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"
	strings:
		$s0 = "Service Control Manager" fullword ascii
		$s1 = "_vsnwprintf" fullword ascii
		$s2 = "Root Agency" fullword ascii
		$s3 = "Root Agency0" fullword ascii
		$s4 = "StartServiceCtrlDispatcherA" fullword ascii
		$s5 = "\\\\?\\UNC" fullword wide
		$s6 = "%ls%ls" fullword wide
	condition:
		all of them and filesize < 15KB and filesize > 10KB 
}

rule Regin_Sample_1 {
	meta:
		description = "Auto-generated rule - file-3665415_sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"
	strings:
		$s0 = "Getting PortName/Identifier failed - %x" fullword ascii
		$s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
		$s2 = "External Naming Failed - Status %x" fullword ascii
		$s3 = "------- Same multiport - different interrupts" fullword ascii
		$s4 = "%x occurred prior to the wait - starting the" fullword ascii
		$s5 = "'user registry info - userPortIndex: %d" fullword ascii
		$s6 = "Could not report legacy device - %x" fullword ascii
		$s7 = "entering SerialGetPortInfo" fullword ascii
		$s8 = "'user registry info - userPort: %x" fullword ascii
		$s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
		$s10 = "Kernel debugger is using port at address %X" fullword ascii
		$s12 = "Release - freeing multi context" fullword ascii
		$s13 = "Serial driver will not load port" fullword ascii
		$s14 = "'user registry info - userAddressSpace: %d" fullword ascii
		$s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
		$s20 = "'user registry info - userIndexed: %d" fullword ascii
	condition:
		all of them and filesize < 110KB and filesize > 80KB
}

rule Regin_Sample_2 {
	meta:
		description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"
	strings:
		$s0 = "\\SYSTEMROOT\\system32\\lsass.exe" fullword wide
		$s1 = "atapi.sys" fullword wide
		$s2 = "disk.sys" fullword wide
		$s3 = "IoGetRelatedDeviceObject" fullword ascii
		$s4 = "HAL.dll" fullword ascii
		$s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" fullword ascii
		$s6 = "PsGetCurrentProcessId" fullword ascii
		$s7 = "KeGetCurrentIrql" fullword ascii
		$s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s9 = "KeSetImportanceDpc" fullword ascii
		$s10 = "KeQueryPerformanceCounter" fullword ascii
		$s14 = "KeInitializeEvent" fullword ascii
		$s15 = "KeDelayExecutionThread" fullword ascii
		$s16 = "KeInitializeTimerEx" fullword ascii
		$s18 = "PsLookupProcessByProcessId" fullword ascii
		$s19 = "ExReleaseFastMutexUnsafe" fullword ascii
		$s20 = "ExAcquireFastMutexUnsafe" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_3 {
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		date = "27.11.14"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"		
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "Service Pack x" fullword wide
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide
		$s3 = "mntoskrnl.exe" fullword wide
		$s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" fullword wide
		$s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
		$s6 = "Service Pack" fullword wide
		$s7 = ".sys" fullword wide
		$s8 = ".dll" fullword wide		
		
		$s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" fullword wide
		$s11 = "IoGetRelatedDeviceObject" fullword ascii
		$s11 = "VMEM.sys" fullword ascii
		$s12 = "RtlGetVersion" fullword wide
		$s14 = "ntkrnlpa.exe" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize > 160KB and filesize < 200KB
}

rule Regin_Sample_Set_1 {
	meta:
		description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "8487a961c8244004c9276979bb4b0c14392fc3b8"
		hash = "bcf3461d67b39a427c83f9e39b9833cfec977c61"		
	strings:
		$s0 = "HAL.dll" fullword ascii
		$s1 = "IoGetDeviceObjectPointer" fullword ascii
		$s2 = "MaximumPortsServiced" fullword wide
		$s3 = "KeGetCurrentIrql" fullword ascii
		$s4 = "ntkrnlpa.exe" fullword ascii
		$s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s6 = "ConnectMultiplePorts" fullword wide
		$s7 = "\\SYSTEMROOT" fullword wide
		$s8 = "IoWriteErrorLogEntry" fullword ascii
		$s9 = "KeQueryPerformanceCounter" fullword ascii
		$s10 = "KeServiceDescriptorTable" fullword ascii
		$s11 = "KeRemoveEntryDeviceQueue" fullword ascii
		$s12 = "SeSinglePrivilegeCheck" fullword ascii
		$s13 = "KeInitializeEvent" fullword ascii
		$s14 = "IoBuildDeviceIoControlRequest" fullword ascii
		$s15 = "KeRemoveDeviceQueue" fullword ascii
		$s16 = "IofCompleteRequest" fullword ascii
		$s17 = "KeInitializeSpinLock" fullword ascii
		$s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
		$s19 = "IoCreateDevice" fullword ascii
		$s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_Set_2 {
	meta:
		description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
		author = "@MalwrSignatures"
		date = "27.11.14"
		hash = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "d%ls%ls" fullword wide
		$s1 = "\\\\?\\UNC" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
		$s3 = "\\\\?\\UNC\\" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
		$s6 = "\\\\.\\Global\\%s" fullword wide
		$s7 = "temp" fullword wide
		$s8 = "\\\\.\\%s" fullword wide
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide		
		
		$s10 = "sscanf" fullword ascii
		$s11 = "disp.dll" fullword ascii
		$s11 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
		$s12 = "%d.%d.%d.%d%c" fullword ascii
		$s13 = "imagehlp.dll" fullword ascii
		$s14 = "%hd %d" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize < 450KB and filesize > 360KB
}

rule apt_regin_legspin {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Legspin module"
	    version = "1.0"
	    last_modified = "2015-01-22"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "29105f46e4d33f66fee346cfd099d1cc"
	strings:
	    $mz="MZ"
	    $a1="sharepw"
	    $a2="reglist"
	    $a3="logdump"
	    $a4="Name:" wide
	    $a5="Phys Avail:"
	    $a6="cmd.exe" wide
	    $a7="ping.exe" wide
	    $a8="millisecs"
	condition:
	    ($mz at 0) and all of ($a*)
}

rule apt_regin_hopscotch {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Hopscotch module"
	    version = "1.0"
	    last_modified = "2015-01-22"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "6c34031d7a5fc2b091b623981a8ae61c"
	strings:

	    $mz="MZ"

	    $a1="AuthenticateNetUseIpc"
	    $a2="Failed to authenticate to"
	    $a3="Failed to disconnect from"
	    $a4="%S\\ipc$" wide
	    $a5="Not deleting..."
	    $a6="CopyServiceToRemoteMachine"
	    $a7="DH Exchange failed"
	    $a8="ConnectToNamedPipes"
	condition:
	    ($mz at 0) and all of ($a*)
}

/* Op Cleaver -------------------------------------------------------------- */

rule OPCLEAVER_BackDoorLogger
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "BackDoorLogger"
		$s2 = "zhuAddress"
	condition:
		all of them
}

rule OPCLEAVER_Jasus
{
	meta:
		description = "ARP cache poisoner used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "pcap_dump_open"
		$s2 = "Resolving IPs to poison..."
		$s3 = "WARNNING: Gateway IP can not be found"
	condition:
		all of them
}

rule OPCLEAVER_LoggerModule
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "%s-%02d%02d%02d%02d%02d.r"
		$s2 = "C:\\Users\\%s\\AppData\\Cookies\\"
	condition:
		all of them
}

rule OPCLEAVER_NetC
{
	meta:
		description = "Net Crawler used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "NetC.exe" wide
		$s2 = "Net Service"
	condition:
		all of them
}

rule OPCLEAVER_ShellCreator2
{
	meta:
		description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "ShellCreator2.Properties"
		$s2 = "set_IV"
	condition:
		all of them
}

rule OPCLEAVER_SmartCopy2
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "SmartCopy2.Properties"
		$s2 = "ZhuFrameWork"
	condition:
		all of them
}

rule OPCLEAVER_SynFlooder
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "your target’s IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."
	condition:
		all of them
}

rule OPCLEAVER_TinyZBot
{
	meta:
		description = "Tiny Bot used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "NetScp" wide
		$s2 = "TinyZBot.Properties.Resources.resources"
		$s3 = "Aoao WaterMark"
		$s4 = "Run_a_exe"
		$s5 = "netscp.exe"
		$s6 = "get_MainModule_WebReference_DefaultWS"
		$s7 = "remove_CheckFileMD5Completed"
		$s8 = "http://tempuri.org/"
		$s9 = "Zhoupin_Cleaver"
	condition:
		(($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9)
}

rule OPCLEAVER_ZhoupinExploitCrew
{
	meta:
		description = "Keywords used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "zhoupin exploit crew" nocase
		$s2 = "zhopin exploit crew" nocase
	condition:
		1 of them
}

rule OPCLEAVER_antivirusdetector
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "getShadyProcess"
		$s2 = "getSystemAntiviruses"
		$s3 = "AntiVirusDetector"
	condition:
		all of them
}

rule OPCLEAVER_csext
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "COM+ System Extentions"
		$s2 = "csext.exe"
		$s3 = "COM_Extentions_bin"
	condition:
		all of them
}

rule OPCLEAVER_kagent
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "kill command is in last machine, going back"
		$s2 = "message data length in B64: %d Bytes"
	condition:
		all of them
}

rule OPCLEAVER_mimikatzWrapper
{
	meta:
		description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "mimikatzWrapper"
		$s2 = "get_mimikatz"
	condition:
		all of them
}

rule OPCLEAVER_pvz_in
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "LAST_TIME=00/00/0000:00:00PM$"
		$s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
	condition:
		all of them
}

rule OPCLEAVER_pvz_out
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "Network Connectivity Module" wide
		$s2 = "OSPPSVC" wide
	condition:
		all of them
}

rule OPCLEAVER_wndTest
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "[Alt]" wide
		$s2 = "<< %s >>:" wide
		$s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
	condition:
		all of them
}

rule OPCLEAVER_zhCat
{
	meta:
		description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
		$s2 = "ABC ( A Big Company )" wide fullword
	condition:
		all of them
}

rule OPCLEAVER_zhLookUp
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "zhLookUp.Properties"
	condition:
		all of them
}

rule OPCLEAVER_zhmimikatz
{
	meta:
		description = "Mimikatz wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
	strings:
		$s1 = "MimikatzRunner"
		$s2 = "zhmimikatz"
	condition:
		all of them
}

rule OPCLEAVER_Parviz_Developer
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Florian Roth"
		score = "70"
	strings:
		$s1 = "Users\\parviz\\documents\\" nocase
	condition:
		$s1 
}

rule OPCLEAVER_CCProxy_Config
{
	meta:
		description = "CCProxy config known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Florian Roth"
		score = "70"
	strings:
		$s1 = "UserName=User-001" fullword ascii
		$s2 = "Web=1" fullword ascii
		$s3 = "Mail=1" fullword ascii
		$s4 = "FTP=0" fullword ascii
		$x1 = "IPAddressLow=78.109.194.114" fullword ascii
	condition:
		all of ($s*) or $x1 
}

/* WATERBUG ----------------------------------------------------------------- */

rule WaterBug_wipbot_2013_core_PDF {
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$PDF = "%PDF-"
		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/ 
		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/
	condition:
		($PDF at 0) and #a > 150 and #b > 200
}

rule WaterBug_wipbot_2013_dll {
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"		
	strings:
		$string1 = "/%s?rank=%s"
		$string2 = "ModuleStart\x00ModuleStop\x00start"
		$string3 = "1156fd22-3443-4344-c4ffff"
		//read file... error..
		$string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"
	condition:
		2 of them
}

rule WaterBug_wipbot_2013_core {
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"			
	strings:
		$mz = "MZ"
		$code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
		$code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
		$code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04} $code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}
	condition:
		$mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}

rule WaterBug_turla_dropper {
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla Dropper"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings: 
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
	condition: 
		all of them
}

rule WaterBug_fa_malware { 
	meta: 
		description = "Symantec Waterbug Attack - FA malware variant"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$mz = "MZ"
		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"
		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku_Win32.sys\x00"
		$string4 = "rk_ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"
	condition:
		($mz at 0) and (any of ($string*))
}

/* pe module memory leak problem


rule WaterBug_turla_dll {
	meta: 
		description = "Symantec Waterbug Attack - Trojan Turla DLL"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"	
	strings:
		$a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
	condition:
		pe.exports("ee") and $a
}

rule WaterBug_sav_dropper {
	meta: 
		description = "Symantec Waterbug Attack - SAV Dropper"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl" 
	strings:
		$mz = "MZ"
		$a = /[a-z]{,10}_x64.sys\x00hMZ\x00/
	condition:
		($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a 
}

*/ 

rule WaterBug_sav {
	meta: 
		description = "Symantec Waterbug Attack - SAV Malware"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl" 	
	strings:
		$mz = "MZ"
		$code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 
					1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }
		$code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 
					17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B
					55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E
					8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC
					3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC
					8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75
					07 }
		$code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 
					75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08
					00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 
					14 81 40 3B C6 72 F5 }
		$code2 =  { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 
					00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 
					8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 
					FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}
	condition:
		($mz at 0) and (($code1a or $code1b or $code1c) and $code2) 
}

/* too many false positives

rule WaterBug_ComRat {
	meta:
		description = "Symantec Waterbug Attack - ComRat Trojan"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl" 	
	strings:
		$mz = "MZ"
		$b = { C6 45 ?? ?? }
		$c = { C6 85 ?? FE FF FF ?? }
		$d = { FF A0 ?? 0? 00 00 }
		$e = { 89 A8 ?? 00 00 00 68 ?? 00 00 00 56 FF D7 8B } 
		$f = { 00 00 48 89 ?? ?? 03 00 00 48 8B }
	condition:
		($mz at 0) and ((#c > 200 and #b > 200 ) or (#d > 40) and (#e > 15 or #f > 30)) 
}

*/

/* Anthem Deep Panda APT */

rule Anthem_DeepPanda_sl_txt_packed {
	meta:
		description = "Anthem Hack Deep Panda - ScanLine sl-txt-packed"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"
	strings:
		$s0 = "Command line port scanner" fullword wide
		$s1 = "sl.exe" fullword wide
		$s2 = "CPports.txt" fullword ascii
		$s3 = ",GET / HTTP/.}" fullword ascii
		$s4 = "Foundstone Inc." fullword wide
		$s9 = " 2002 Foundstone Inc." fullword wide
		$s15 = ", Inc. 2002" fullword ascii
		$s20 = "ICMP Time" fullword ascii
	condition:
		all of them
}

rule Anthem_DeepPanda_lot1 {
	meta:
		description = "Anthem Hack Deep Panda - lot1.tmp-pwdump"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"
	strings:
		$s0 = "Unable to open target process: %d, pid %d" fullword ascii
		$s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
		$s2 = "Target: Failed to load SAM functions." fullword ascii
		$s5 = "Error writing the test file %s, skipping this share" fullword ascii
		$s6 = "Failed to create service (%s/%s), error %d" fullword ascii
		$s8 = "Service start failed: %d (%s/%s)" fullword ascii
		$s12 = "PwDump.exe" fullword ascii
		$s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
		$s14 = ":\\\\.\\pipe\\%s" fullword ascii
		$s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
		$s16 = "dump logon session" fullword ascii
		$s17 = "Timed out waiting to get our pipe back" fullword ascii
		$s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
		$s20 = "%s\\%s.exe" fullword ascii
	condition:
		10 of them
}

rule Anthem_DeepPanda_htran_exe {
	meta:
		description = "Anthem Hack Deep Panda - htran-exe"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
	strings:
		$s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
		$s2 = "e:\\VS 2008 Project\\htran\\Release\\htran.pdb" fullword ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s5 = "[-] ERROR: Must supply logfile name." fullword ascii
		$s6 = "[-] There is a error...Create a new connection." fullword ascii
		$s7 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s8 = "======================== htran V%s =======================" fullword ascii
		$s9 = "[-] Socket Listen error." fullword ascii
		$s10 = "[-] ERROR: open logfile" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s12 = "[+] Make a Connection to %s:%d ......" fullword ascii
		$s14 = "Recv %5d bytes from %s:%d" fullword ascii
		$s15 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s16 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s17 = "[+] Accept a Client on port %d from %s ......" fullword ascii
		$s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
	condition:
		10 of them
}

rule Anthem_DeepPanda_Trojan_Kakfum {
	meta:
		description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
		author = "Florian Roth"
		date = "2015/02/08"
		hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
		hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"
	strings:
		$s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
		$s1 = "%s\\sqlsrv32.dll" fullword ascii
		$s2 = "%s\\sqlsrv64.dll" fullword ascii
		$s3 = "%s\\%d.tmp" fullword ascii
		$s4 = "ServiceMaix" fullword ascii
		$s15 = "sqlserver" fullword ascii
	condition:
		all of them
}

rule Dexter_Malware {
	meta:
		description = "Detects the Dexter Trojan/Agent http://goo.gl/oBvy8b"
		author = "Florian Roth"
		reference = "http://goo.gl/oBvy8b"
		date = "2015/02/10"
		score = 70
	strings:
		$s0 = "Java Security Plugin" fullword wide
		$s1 = "%s\\%s\\%s.exe" fullword wide
		$s2 = "Sun Java Security Plugin" fullword wide
		$s3 = "\\Internet Explorer\\iexplore.exe" fullword wide
	condition:
		all of them
}

rule Enfal_Malware {
	meta:
		description = "Detects a certain type of Enfal Malware"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/02/10"
		hash = "9639ec9aca4011b2724d8e7ddd13db19913e3e16"
		score = 60
	strings:
		$s0 = "POWERPNT.exe" fullword ascii
		$s1 = "%APPDATA%\\Microsoft\\Windows\\" fullword ascii
		$s2 = "%HOMEPATH%" fullword ascii
		$s3 = "Server2008" fullword ascii
		$s4 = "Server2003" fullword ascii
		$s5 = "Server2003R2" fullword ascii
		$s6 = "Server2008R2" fullword ascii
		$s9 = "%HOMEDRIVE%" fullword ascii
		$s13 = "%ComSpec%" fullword ascii
	condition:
		all of them
}

rule Enfal_Malware_Backdoor {
	meta:
		description = "Generic Rule to detect the Enfal Malware"
		author = "Florian Roth"
		date = "2015/02/10"
		super_rule = 1
		hash0 = "6d484daba3927fc0744b1bbd7981a56ebef95790"
		hash1 = "d4071272cc1bf944e3867db299b3f5dce126f82b"
		hash2 = "6c7c8b804cc76e2c208c6e3b6453cb134d01fa41"
		score = 60
	strings:
		$mz = { 4d 5a }
			
		$x1 = "Micorsoft Corportation" fullword wide
		$x2 = "IM Monnitor Service" fullword wide
		
		$s1 = "imemonsvc.dll" fullword wide
		$s2 = "iphlpsvc.tmp" fullword
		
		$z1 = "urlmon" fullword
		$z2 = "Registered trademarks and service marks are the property of their respec" wide		
		$z3 = "XpsUnregisterServer" fullword
		$z4 = "XpsRegisterServer" fullword
		$z5 = "{53A4988C-F91F-4054-9076-220AC5EC03F3}" fullword
	condition:
		( $mz at 0 ) and 
		( 
			1 of ($x*) or 
			( all of ($s*) and all of ($z*) )
		)
}

rule TrojanDownloader {
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		author = "Florian Roth"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii
			
		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii						

		$s5 = "SetConsoleMode" fullword ascii		
		$s9 = "TerminateProcess" fullword ascii	
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii		
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii
	condition:
		$x1 and $x2 and ( all of ($s*) ) and filesize < 35000
}

/* Equation APT ------------------------------------------------------------ */

rule apt_equation_exploitlib_mutexes {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC" 
        $a5="cnFormVoidFBC"
    condition:
        (($mz at 0) and any of ($a*))
}

rule apt_equation_doublefantasy_genericresource {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}

rule apt_equation_doublefantasy_genericresource {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*))  and filesize < 500000
}

rule apt_equation_doublefantasy_genericresource {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*))  and filesize < 500000
}

/* Equation Group - Kaspersky ---------------------------------------------- */

rule Equation_Kaspersky_TripleFantasy_1 {
	meta:
		description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
	strings:
		$mz = { 4d 5a }
	
		$s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
		$s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
		$s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
		$s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
		$s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
		$s5 = "Chrome" fullword wide
		$s6 = "StringIndex" fullword ascii
		
		$x1 = "itemagic.net@443" fullword wide
		$x2 = "team4heat.net@443" fullword wide
		$x5 = "62.216.152.69@443" fullword wide
		$x6 = "84.233.205.37@443" fullword wide
		
		$z1 = "www.microsoft.com@80" fullword wide
		$z2 = "www.google.com@80" fullword wide
		$z3 = "127.0.0.1:3128" fullword wide
	condition:
		( $mz at 0 ) and filesize < 300000 and
		( 
			( all of ($s*) and all of ($z*) ) or 
			( all of ($s*) and 1 of ($x*) ) 
		)
}

rule Equation_Kaspersky_DoubleFantasy_1 {
	meta:
		description = "Equation Group Malware - DoubleFantasy"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
	strings:
		$mz = { 4d 5a }
		
		$z1 = "msvcp5%d.dll" fullword ascii
		
		$s0 = "actxprxy.GetProxyDllInfo" fullword ascii
		$s3 = "actxprxy.DllGetClassObject" fullword ascii
		$s5 = "actxprxy.DllRegisterServer" fullword ascii
		$s6 = "actxprxy.DllUnregisterServer" fullword ascii
		
		$x1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" ascii
		$x2 = "191H1a1" fullword ascii
		$x3 = "November " fullword ascii
		$x4 = "abababababab" fullword ascii
		$x5 = "January " fullword ascii
		$x6 = "October " fullword ascii
		$x7 = "September " fullword ascii
	condition:
		( $mz at 0 ) and filesize < 350000 and
		(
			( $z1 ) or 
			( all of ($s*) and 6 of ($x*) )
		)
}

rule Equation_Kaspersky_GROK_Keylogger {
	meta:
		description = "Equation Group Malware - GROK keylogger"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"
	strings:
		$mz = { 4d 5a }
		$s0 = "c:\\users\\rmgree5\\" ascii
		$s1 = "msrtdv.sys" fullword wide
		
		$x1 = "svrg.pdb" fullword ascii
		$x2 = "W32pServiceTable" fullword ascii
		$x3 = "In forma" fullword ascii
		$x4 = "ReleaseF" fullword ascii
		$x5 = "criptor" fullword ascii
		$x6 = "astMutex" fullword ascii
		$x7 = "ARASATAU" fullword ascii
		$x8 = "R0omp4ar" fullword ascii
		
		$z1 = "H.text" fullword ascii
		$z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword
	condition:
		( $mz at 0 ) and filesize < 250000 and 
		(
			$s0 or
			( $s1 and 6 of ($x*) ) or
			( 6 of ($x*) and all of ($z*) )
		)	
}

rule Equation_Kaspersky_GreyFishInstaller {
	meta:
		description = "Equation Group Malware - Grey Fish"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
	strings:
		$s0 = "DOGROUND.exe" fullword wide
		$s1 = "Windows Configuration Services" fullword wide
		$s2 = "GetMappedFilenameW" fullword ascii
	condition:
		all of them
}

rule Equation_Kaspersky_EquationDrugInstaller {
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
	strings:
		$mz = { 4d 5a }
		
		$s0 = "\\system32\\win32k.sys" fullword wide
		$s1 = "ALL_FIREWALLS" fullword ascii
		
		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide
	condition:
		( $mz at 0 ) and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EquationLaserInstaller {
	meta:
		description = "Equation Group Malware - EquationLaser Installer"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"
	strings:
		$mz = { 4d 5a }
		$s0 = "Failed to get Windows version" fullword ascii
		$s1 = "lsasrv32.dll and lsass.exe" fullword wide
		$s2 = "\\\\%s\\mailslot\\%s" fullword ascii
		$s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
		$s4 = "lsasrv32.dll" fullword ascii
		$s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii
		$s6 = "%s %02x %s" fullword ascii
		$s7 = "VIEWERS" fullword ascii
		$s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
	condition:
		( $mz at 0 ) and filesize < 250000 and 6 of ($s*)
}

rule Equation_Kaspersky_FannyWorm {
	meta:
		description = "Equation Group Malware - Fanny Worm"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"
	strings:
		$mz = { 4d 5a }
	
		$s1 = "x:\\fanny.bmp" fullword ascii
		$s2 = "32.exe" fullword ascii	
		$s3 = "d:\\fanny.bmp" fullword ascii
	
		$x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
		$x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
		$x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
		$x4 = "\\system32\\win32k.sys" fullword wide
		$x5 = "\\AGENTCPD.DLL" fullword ascii
		$x6 = "agentcpd.dll" fullword ascii
		$x7 = "PADupdate.exe" fullword ascii
		$x8 = "dll_installer.dll" fullword ascii		
		$x9 = "\\restore\\" fullword ascii
		$x10 = "Q:\\__?__.lnk" fullword ascii
		$x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
		$x12 = "\\shelldoc.dll" fullword ascii
		$x13 = "file size = %d bytes" fullword ascii
		$x14 = "\\MSAgent" fullword ascii
		$x15 = "Global\\RPCMutex" fullword ascii
		$x16 = "Global\\DirectMarketing" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 300000 and 
		( 
			( 2 of ($s*) ) or
			( 1 of ($s*) and 6 of ($x*) ) or
			( 14 of ($x*) )
		)
}

rule Equation_Kaspersky_HDD_reprogramming_module {
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
	strings:
		$mz = { 4d 5a }
		$s0 = "nls_933w.dll" fullword ascii
		
		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 300000 and all of ($s*)
}

rule Equation_Kaspersky_EOP_Package {
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
	strings:
		$mz = { 4d 5a }
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide
	condition:
		( $mz at 0 ) and filesize < 100000 and all of ($s*)
}

rule Equation_Kaspersky_TripleFantasy_Loader {
	meta:
		description = "Equation Group Malware - TripleFantasy Loader"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
	strings:
		$mz = { 4d 5a }
		
		$x1 = "Original Innovations, LLC" fullword wide
		$x2 = "Moniter Resource Protocol" fullword wide
		$x3 = "ahlhcib.dll" fullword wide	
	
		$s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
		$s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
		$s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
		$s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
		$s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
		$s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}

