/*
	Yara Rule Set
	Author: RSA RESEARCH, Florian Roth
	Date: 2015-11-23
	Identifier: GlassRAT
*/

rule glassRAT
{
	meta:
		author = "RSA RESEARCH"
		date = "3 Nov 2015"
      description = "Detects GlassRAT by RSA (modified by Florian Roth - speed improvements)"
		Info = "GlassRat"
		/* MD5s
			37adc72339a0c2c755e7fef346906330
			59b404076e1af7d0faae4a62fa41b69f
			5c17395731ec666ad0056d3c88e99c4d
			e98027f502f5acbcb5eda17e67a21cdc
			87a965cf75b2da112aea737220f2b5c2
			22e01495b4419b564d5254d2122068d9
			42b57c0c4977a890ecb0ea9449516075
			b7f2020208ebd137616dadb60700b847	*/
	strings:
		$bin1 = {85 C0 B3 01} 		/* 	test    eax, eax
										  mov     bl, 1 */
		// $bin2 = {34 02}				// xor     al, 2 ---> XOR key for rundll32.exe
		$bin3 = {68 4C 50 00 10}	// push    offset KeyName  ; "2"
		$bin4 = {68 48 50 00 10}	// push    offset a3       ; "3"
		$bin5 = {68 44 50 00 10}	// push    offset a4       ; "4"
		$hs = {CB FF 5D C9 AD 3F 5B A1 54 13 FE FB 05 C6 22}  // Initial Handshake ---> can be added or removed for hunting for different variants
		//$re1  = {50 00 00 00}
		//$re2  = {BB 01 00 00}
		// Dwords of C2 Ports (80 | 443 | 53) 2 -3 times
		$s1 = "pwlfnn10,gzg" // rundll32.exe XOR 02
		$s2 = "AddNum"
		$s3 = "ServiceMain"
		$s4 = "The Window"
		$s5 = "off.dat"
	condition:
		all of ($bin*) and $hs and 3 of ($s*) //The conditions can be adjusted for hunting for different variants
}

rule GlassRAT_Generic {
	meta:
		description = "Detects GlassRAT Malware"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/peering-into-glassrat/"
		date = "2015-11-23"
		score = 80
		hash1 = "30d26aebcee21e4811ff3a44a7198a5c519843a24f334880384a7158e07ae399"
		hash2 = "3bdeb3805e9230361fb93c6ffb0bfec8d3aee9455d95b2428c7f6292d387d3a4"
		hash3 = "79993f1912958078c4d98503e00dc526eb1d0ca4d020d17b010efa6c515ca92e"
		hash4 = "a9b30b928ebf9cda5136ee37053fa045f3a53d0706dcb2343c91013193de761e"
		hash5 = "c11faf7290299bb13925e46d040ed59ab3ca8938eab1f171aa452603602155cb"
		hash6 = "d95fa58a81ab2d90a8cbe05165c00f9c8ad5b4f49e98df2ad391f5586893490d"
		hash7 = "f1209eb95ce1319af61f371c7f27bf6846eb90f8fd19e8d84110ebaf4744b6ea"
	strings:
		$s1 = "cmd.exe /c %s" fullword ascii
		$s2 = "update.dll" fullword ascii
		$s3 = "SYSTEM\\CurrentControlSet\\Services\\RasAuto\\Parameters" fullword ascii
		$s4 = "%%temp%%\\%u" fullword ascii
		$s5 = "\\off.dat" fullword ascii
		$s6 = "rundll32 \"%s\",AddNum" fullword ascii
		$s7 = "cmd.exe /c erase /F \"%s\"" fullword ascii
		$s8 = "SYSTEM\\ControlSet00%d\\Services\\RasAuto" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 15MB and 5 of them
}
