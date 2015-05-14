
rule Backdoor_Naikon_APT_Sample1 {
	meta:
		description = "Detects backdoors used in the Naikon APT"
		author = "Florian Roth"
		reference = "https://goo.gl/7vHyvh"
		date = "2015-05-14"
		hash = "76de44b1b7e045e8ebfb0f84f4eece5fcc8cb0ed"
	strings:
		$x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
		$x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
		$x2 = "greensky27.vicp.net" fullword ascii
		
		$s1 = "User-Agent: webclient" fullword ascii
		$s2 = "\\User.ini" fullword ascii
		$s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
		$s4 = "\\UserProfile.dll" fullword wide
		$s5 = "Connection:Keep-Alive: %d" fullword ascii
		$s6 = "Referer: http://%s:%d/" fullword ascii
		$s7 = "%s %s %s %d %d %d " fullword ascii
		$s8 = "%s--%s" fullword wide
		$s9 = "Run File Success!" fullword wide
		$s10 = "DRIVE_REMOTE" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and
		(
			1 of ($x*) or 7 of ($s*)
		)
}

