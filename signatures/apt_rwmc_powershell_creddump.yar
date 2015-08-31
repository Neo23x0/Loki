/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-31
	Identifier: RWMC Powershell Credential Dumper
*/

rule Reveal_MemoryCredentials {
	meta:
		description = "Auto-generated rule - file Reveal-MemoryCredentials.ps1"
		author = "Florian Roth"
		reference = "https://github.com/giMini/RWMC/"
		date = "2015-08-31"
		hash = "893c26818c424d0ff549c1fbfa11429f36eecd16ee69330c442c59a82ce6adea"
	strings:
		$s1 = "$dumpAProcessPath = \"C:\\Windows\\temp\\msdsc.exe\"" fullword ascii
		$s2 = "$user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}" fullword ascii
		$s3 = "Copy-Item -Path \"\\\\$computername\\\\c$\\windows\\temp\\lsass.dmp\" -Destination \"$logDirectoryPath\"" fullword ascii
		$s4 = "if($backupOperatorsFlag -eq \"true\") {$loginPlainText = $loginPlainText + \" = Backup Operators\"}            " fullword ascii
	condition:
		filesize < 200KB and 1 of them
}

rule MiniDumpTest_msdsc {
	meta:
		description = "Auto-generated rule - file msdsc.exe"
		author = "Florian Roth"
		reference = "https://github.com/giMini/RWMC/"
		date = "2015-08-31"
		hash = "477034933918c433f521ba63d2df6a27cc40a5833a78497c11fb0994d2fd46ba"
	strings:
		$s1 = "MiniDumpTest1.exe" fullword wide
		$s2 = "MiniDumpWithTokenInformation" fullword ascii
		$s3 = "MiniDumpTest1" fullword wide
		$s6 = "Microsoft 2008" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

