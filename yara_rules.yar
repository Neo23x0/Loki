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
