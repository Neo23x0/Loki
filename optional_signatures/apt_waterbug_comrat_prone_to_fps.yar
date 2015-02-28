rule WaterBug_ComRat {
	meta:
		description = "Symantec Waterbug Attack - ComRat Trojan - prone to False Positives - use with care"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl" 	
	strings:
		$mz = "MZ"
		$b = { C6 45 ?? ?? }
		$c = { C6 85 ?? FE FF FF ?? }
		$d = { FF A0 ?? 0? 00 00 }
		$e = { 89 A8 ?? 00 00 00 68 ?? 00 00 00 56 FF D7 8B } 
		$f = { 00 00 48 89 ?? ?? 03 00 00 48 8B }
	condition:
		($mz at 0) and ((#c > 200 and #b > 200 ) or (#d > 40) and (#e > 15 or #f > 30)) 
}