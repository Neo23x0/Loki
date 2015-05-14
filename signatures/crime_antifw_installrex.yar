
rule PUP_InstallRex_AntiFWb {
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth"
		date = "2015-05-13"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		score = 65
	strings:
		$s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
		$s7 = "GetModuleFileName() failed => %u" fullword ascii
		$s8 = "TSULoader.exe" fullword wide
		$s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
		$s17 = "Tsu%08lX.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}