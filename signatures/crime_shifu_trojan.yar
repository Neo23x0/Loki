/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-09-01
	Identifier: Shifu
*/

rule Shifu_Banking_Trojan {
	meta:
		description = "Detects Shifu Banking Trojan"
		author = "Florian Roth"
		reference = "https://securityintelligence.com/shifu-masterful-new-banking-trojan-is-attacking-14-japanese-banks/"
		date = "2015-09-01"
		hash1 = "4ff1ebea2096f318a2252ebe1726bcf3bbc295da9204b6c720b5bbf14de14bb2"
		hash2 = "4881c7d89c2b5e934d4741a653fbdaf87cc5e7571b68c723504069d519d8a737"
	strings:
		$x1 = "c:\\oil\\feet\\Seven\\Send\\Gather\\Dividerail.pdb" fullword ascii
		
		$s1 = "listen above" fullword wide
		$s2 = "familycould cost" fullword wide
		$s3 = "SetSystemTimeAdjustment" fullword ascii /* Goodware String - occured 33 times */
		$s4 = "PeekNamedPipe" fullword ascii /* Goodware String - occured 347 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and ($x1 or all of ($s*))
}
