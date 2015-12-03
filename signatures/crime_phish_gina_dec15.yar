/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-02
	Identifier: Phishing Gina Harrowell Dez 2015
*/

rule PHISH_02Dez2015_dropped_p0o6543f_1 {
	meta:
		description = "Phishing Wave - file p0o6543f.exe"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210"
	strings:
		$s1 = "netsh.exe" fullword wide
		$s2 = "routemon.exe" fullword wide
		$s3 = "script=" fullword wide /* Goodware String - occured 4 times */
		$s4 = "disconnect" fullword wide /* Goodware String - occured 14 times */
		$s5 = "GetClusterResourceTypeKey" fullword ascii /* Goodware String - occured 17 times */
		$s6 = "QueryInformationJobObject" fullword ascii /* Goodware String - occured 34 times */
		$s7 = "interface" fullword wide /* Goodware String - occured 52 times */
		$s8 = "connect" fullword wide /* Goodware String - occured 61 times */
		$s9 = "FreeConsole" fullword ascii /* Goodware String - occured 91 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule PHISH_02Dez2015_dropped_p0o6543f_2 {
	meta:
		description = "Phishing Wave used MineExplorer Game by WangLei - file p0o6543f.exe.4"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-03"
		hash1 = "d6b21ded749b57042eede07c3af1956a3c9f1faddd22d2f78e43003a11ae496f"
		hash2 = "561b16643992b92d37cf380bc2ed7cd106e4dcaf25ca45b4ba876ce59533fb02"
	strings:
		$s1 = "Email: W0067@990.net" fullword wide
		$s2 = "MineExplorer Version 1.0" fullword wide
		$s6 = "Copy Rights by WangLei 1999.4" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658 {
	meta:
		description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash1 = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
		hash2 = "e6c5b55586e9d99551adc27a0fc9c080cea6201fae60104b82d5a2ec518fafb6"
		hash3 = "80f278b7268ea6814f8b336e07c5f4b03289519e199fbe4cbd9ef6a38cf25df6"
		hash4 = "3a0a758525883a049a42312e46a023076c31af23b5e8e5b81fec56d51e4c80fb"
		hash5 = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
		hash6 = "d9db7d32949c4df6a5d9d0292b576ae19681be7b6e0684df57338390e87fc6d6"
		hash7 = "7bb705701ae73d377f6091515a140f0af57703719a67da9a60fad4544092ee6c"
		hash8 = "e743c6e7749ab1046a2beea8733d7c8386ea60b43492bb4f0769ced6a2cee66d"
	strings:
		$s1 = "Execute" ascii
		$s2 = "Process WriteParameterFiles" fullword ascii
		$s3 = "WScript.Shell" fullword ascii
		$s4 = "STOCKMASTER" fullword ascii
		$s5 = "InsertEmailFax" ascii
	condition:
		uint16(0) == 0xcfd0 and filesize < 200KB and all of them
}
