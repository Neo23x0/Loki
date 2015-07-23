/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-07-22
	Identifier: CloudDuke
*/

/* Rule Set ----------------------------------------------------------------- */

rule CloudDuke_Malware {
	meta:
		description = "Detects CloudDuke Malware"
		author = "Florian Roth"
		reference = "https://www.f-secure.com/weblog/archives/00002822.html"
		date = "2015-07-22"
		score = 60
		hash = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
	strings:
		$s1 = "ProcDataWrap" fullword ascii
		$s2 = "imagehlp.dll" fullword ascii
		$s3 = "dnlibsh" fullword ascii
		$s4 = "%ws_out%ws" fullword wide
		$s5 = "Akernel32.dll" fullword wide

		$op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b } /* Opcode */
		$op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f } /* Opcode */
		$op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 720KB and 4 of ($s*) and 1 of ($op*)
}

/* Inverse Rules ----------------------------------------------------------- */
/* Warning: this rule works with the external variable 'filename' only       */

rule Acrotray_Anomaly {
	meta:
		description = "Detects an acrotray.exe that does not contain the usual strings"
		author = "Florian Roth"
		score = 75
	strings:
		$s1 = "PDF/X-3:2002" fullword wide
		$s2 = "AcroTray - Adobe Acrobat Distiller helper application" fullword wide
		$s3 = "MS Sans Serif" fullword wide
		$s4 = "COOLTYPE.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB 
		and ( filename == "acrotray.exe" or filename == "AcroTray.exe" )
		and not all of ($s*) 	
}

/* Super Rules ------------------------------------------------------------- */

rule SFXRAR_Acrotray {
	meta:
		description = "Most likely a malicious file acrotray in SFX RAR / CloudDuke APT 5442.1.exe, 5442.2.exe"
		author = "Florian Roth"
		reference = "https://www.f-secure.com/weblog/archives/00002822.html"
		date = "2015-07-22"
		super_rule = 1
		score = 70
		hash1 = "51e713c7247f978f5836133dd0b8f9fb229e6594763adda59951556e1df5ee57"
		hash2 = "5d695ff02202808805da942e484caa7c1dc68e6d9c3d77dc383cfa0617e61e48"
		hash3 = "56531cc133e7a760b238aadc5b7a622cd11c835a3e6b78079d825d417fb02198"
	strings:
		$s1 = "winrarsfxmappingfile.tmp" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "GETPASSWORD1" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "acrotray.exe" fullword ascii
		$s4 = "CryptUnprotectMemory failed" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 2449KB and all of them
}
