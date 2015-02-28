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

rule apt_equation_equationlaser_runtimeclasses {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the EquationLaser malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "https://securelist.com/blog/"
	strings:
	    $a1="?a73957838_2@@YAXXZ"
	    $a2="?a84884@@YAXXZ"
	    $a3="?b823838_9839@@YAXXZ"
	    $a4="?e747383_94@@YAXXZ"
	    $a5="?e83834@@YAXXZ"
	    $a6="?e929348_827@@YAXXZ"
	condition:
	    any of them
}

rule apt_equation_cryptotable {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the crypto library used in Equation group malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "https://securelist.com/blog/"
	strings:
	    $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}
	condition:
	    $a
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

/* Rule generated from the mentioned keywords */

rule Equation_Kaspersky_SuspiciousString {
	meta:
		description = "Equation Group Malware - suspicious string found in sample"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/17"
		score = 60
	strings:
		$mz = { 4d 5a }
		
		$s1 = "i386\\DesertWinterDriver.pdb" fullword
		$s2 = "Performing UR-specific post-install..."
		$s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
		$s4 = "STRAITSHOOTER30.exe"
		$s5 = "standalonegrok_2.1.1.1"
		$s6 = "c:\\users\\rmgree5\\"
	condition:
		( $mz at 0 ) and filesize < 500000 and all of ($s*) 
}