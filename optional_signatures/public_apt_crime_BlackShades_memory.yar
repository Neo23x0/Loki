rule BlackShades : rat
{
	meta:
		description = "BlackShades"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 

	strings:
		$a = { 42 00 6C 00 61 00 63 00 6B 00 73 00 68 00 61 00 64 00 65 00 73 }
		$b = { 36 00 3C 00 32 00 20 00 32 00 32 00 26 00 31 00 39 00 3E 00 1D 00 17 00 17 00 1C 00 07 00 1B 00 03 00 07 00 28 00 23 00 0C 00 1D 00 10 00 1B 00 12 00 00 00 28 00 37 00 10 00 01 00 06 00 11 00 0B 00 07 00 22 00 11 00 17 00 00 00 1D 00 1B 00 0B 00 2F 00 26 00 01 00 0B }
		$c = { 62 73 73 5F 73 65 72 76 65 72 }
		$d = { 43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44 }
		$e = { 6D 6F 64 49 6E 6A 50 45 }
		$apikey = "f45e373429c0def355ed9feff30eff9ca21eec0fafa1e960bea6068f34209439"

	condition:
		any of ($a, $b, $c, $d, $e) or $apikey		
}