
rule Havex_Trojan_PHP_Server
	{
	meta:
		description = "Detects the PHP server component of the Havex RAT"
		date = "2014-06-24"
		author = "Florian Roth"
		reference = "http://goo.gl/GO5mB1"
	strings:
	    $s1 = "havex--></body></head>"
		$s2 = "ANSWERTAG_START"
		$s3 = "PATH_BLOCKFILE"
	condition:
	    all of them
}

rule Havex_Trojan
	{
	meta:
		description = "Detects the Havex RAT malware"
		date = "2014-06-24"
		author = "Florian Roth"
		reference = "http://goo.gl/GO5mB1"
		hash = "7933809aecb1a9d2110a6fd8a18009f2d9c58b3c7dbda770251096d4fcc18849"
	strings:
		$magic = { 4d 5a }	
	
	    $s1 = "Start finging of LAN hosts..." fullword wide
		$s2 = "Finding was fault. Unexpective error" fullword wide
		$s3 = "Hosts was't found." fullword wide
		$s4 = "%s[%s]!!!EXEPTION %i!!!" fullword wide
		$s5 = "%s  <%s> (Type=%i, Access=%i, ID='%s')" fullword wide
		$s6 = "Was found %i hosts in LAN:" fullword wide
		
		$x1 = "MB Connect Line GmbH" wide fullword
		$x2 = "mbCHECK" wide fullword
	condition:
	    $magic at 0 and ( 2 of ($s*) or all of ($x*) )
}

