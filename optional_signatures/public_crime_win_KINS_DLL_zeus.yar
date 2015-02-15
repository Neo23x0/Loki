rule KINS_DLL_zeus {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match default bot in KINS leaked dropper, Zeus"
	strings:
		// Network protocol
		$n1 = "%BOTID%" fullword
		$n2 = "%opensocks%" fullword
		$n3 = "%openvnc%" fullword
		$n4 = /Global\\(s|v)_ev/ fullword
		// Crypted strings
		$s1 = "\x72\x6E\x6D\x2C\x36\x7D\x76\x77"
		$s2 = "\x18\x04\x0F\x12\x16\x0A\x1E\x08\x5B\x11\x0F\x13"
		$s3 = "\x39\x1F\x01\x07\x15\x19\x1A\x33\x19\x0D\x1F"
		$s4 = "\x62\x6F\x71\x78\x63\x61\x7F\x69\x2D\x67\x79\x65"
		$s5 = "\x6F\x69\x7F\x6B\x61\x53\x6A\x7C\x73\x6F\x71"
	condition:
		all of ($n*) and 1 of ($s*)
}