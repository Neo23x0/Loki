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