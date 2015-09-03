/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-09-03
	Identifier: Carbanak Rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule Carbanak_0915_1 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
		hash = "c660127e620eda98edfe1b10812d9e1e57bb425fb711e254f682425a5aafc36e"
	strings:
		$s1 = "evict1.pdb" fullword ascii
		$s2 = "http://testing.corp 0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule Carbanak_0915_2 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
		hash = "d571113f803283c64a351736a3099cc86d9edcd84a8bd762587ce5c580c771d6"
	strings:
		$x1 = "8Rkzy.exe" fullword wide

		$s1 = "Export Template" fullword wide
		$s2 = "Session folder with name '%s' already exists." fullword ascii
		$s3 = "Show Unconnected Endpoints (Ctrl+U)" fullword ascii
		$s4 = "Close All Documents" fullword wide
		$s5 = "Add &Resource" fullword ascii
		$s6 = "PROCEXPLORER" fullword wide /* Goodware String - occured 1 times */
		$s7 = "AssocQueryKeyA" fullword ascii /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and ( $x1 or all of ($s*) )
}

rule Carbanak_0915_3 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
		hash = "d718503f6403355702d021b08404b47692b2a13d9fd01bd7516f7074b73e9b7b"
	strings:
		$s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
		$s2 = "SHInvokePrinterCommandA" fullword ascii
		$s3 = "Ycwxnkaj" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}
