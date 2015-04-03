rule Explosive_EXE : APT { 
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Check Point Software Technologies Inc." 
	strings:
		$DLD_S = "DLD-S:" 
		$DLD_E = "DLD-E:"
	condition:
		all of them and
        uint16(0) == 0x5A4D
}

rule Explosion_Sample_1 {
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT - file b74bd5660baf67038353136978ed16dbc7d105c60c121cf64c61d8f3d31de32c"
		author = "Florian Roth"
		reference = "http://goo.gl/5vYaNb"
		date = "2015/04/03"
		score = 70
		hash = "c97693ecb36247bdb44ab3f12dfeae8be4d299bb"
	strings:
		$s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
		$s9 = "WinAutologon From Winlogon Reg" fullword ascii
		$s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
		$s11 = "IE:Password-Protected sites" fullword ascii
		$s12 = "\\his.sys" fullword ascii
		$s13 = "HTTP Password" fullword ascii
		$s14 = "\\data.sys" fullword ascii
		$s15 = "EL$_RasDefaultCredentials#0" fullword wide
		$s17 = "Office Outlook HTTP" fullword ascii
		$s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii
	condition:
		all of them and  
        uint16(0) == 0x5A4D
}

rule Explosion_Sample_2 {
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT - file bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
		author = "Florian Roth"
		reference = "http://goo.gl/5vYaNb"
		date = "2015/04/03"
		score = 70
		hash = "62fe6e9e395f70dd632c70d5d154a16ff38dcd29"
	strings:
		$s0 = "serverhelp.dll" fullword wide
		$s1 = "Windows Help DLL" fullword wide
		$s5 = "SetWinHoK" fullword ascii
	condition:
		all of them and  
        uint16(0) == 0x5A4D
}

rule Explosion_Generic_1 {
	meta:
		description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/04/03"
		score = 70
		super_rule = 1
		hash0 = "d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408c821"
		hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
		hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
		hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
		hash4 = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"
	strings:
		$s0 = "autorun.exe" fullword
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CL"
		$s2 = "%drp.exe" fullword
		$s3 = "%s_%s%d.exe" fullword
		$s4 = "open=autorun.exe" fullword
		$s5 = "http://www.microsoft.com/en-us/default.aspx" fullword
		$s10 = "error.renamefile" fullword
		$s12 = "insufficient lookahead" fullword
		$s13 = "%s %s|" fullword
		$s16 = ":\\autorun.exe" fullword
	condition:
		7 of them and  
        uint16(0) == 0x5A4D 
}

rule Explosive_UA {
	meta:
		description = "Explosive Malware Embedded User Agent - Volatile Cedar APT http://goo.gl/HQRCdw"
		author = "Florian Roth"
		reference = "http://goo.gl/HQRCdw"
		date = "2015/04/03"
		score = 60
	strings:	
		$x1 = "Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CLR 2.0.50727)" fullword
	condition:
		$x1 and  
        uint16(0) == 0x5A4D 
}

rule Webshell_Caterpillar_ASPX {
	meta:
		description = "Volatile Cedar Webshell - from file caterpillar.aspx"
		author = "Florian Roth"
		reference = "http://goo.gl/emons5"
		date = "2015/04/03"
		super_rule = 1
		hash0 = "af4c99208fb92dc42bc98c4f96c3536ec8f3fe56"
	strings:
		$s0 = "Dim objNewRequest As WebRequest = HttpWebRequest.Create(sURL)" fullword
		$s1 = "command = \"ipconfig /all\"" fullword
		$s3 = "For Each xfile In mydir.GetFiles()" fullword
		$s6 = "Dim oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s10 = "recResult = adoConn.Execute(strQuery)" fullword
		$s12 = "b = Request.QueryString(\"src\")" fullword
		$s13 = "rw(\"<a href='\" + link + \"' target='\" + target + \"'>\" + title + \"</a>\")" fullword
	condition:
		all of them
}