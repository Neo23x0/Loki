rule LSASS_memory_dump_file {
	meta:
		description = "Detects a LSASS memory dump file"
		author = "Florian Roth"
		date = "2015/03/31"
		score = 50
	strings:
		$s1 = "lsass.exe" 
		$s2 = "WDigest" fullword ascii
		$s3 = "NTLM Authentication" fullword wide
		$s4 = "wdigest.DLL" wide
		$s5 = "NTLM Security Package" ascii
	condition:
        uint32(0) == 0x504D444D and all of them
}

