/*
	Operation WoolenGoldfish Rules (Trendmicro Report)
	v0.1 25.03.2015

	These rules detect 26 of the samples mentioned in the report
	Reference: http://blog.trendmicro.com/trendlabs-security-intelligence/operation-woolen-goldfish-when-kittens-go-phishing/

	Tested against 20GB goodware sample archiv - pls report back false positives
	on LOKI's github page https://github.com/Neo23x0/Loki/issues

*/

rule WoolenGoldfish_Sample_1 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
	strings:
		$s1 = "Cannot execute (%d)" fullword ascii
		$s16 = "SvcName" fullword ascii
	condition:
		all of them
}

rule WoolenGoldfish_Sample_2 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		hash = "0f4bf1d89d080ed318597754e6d3930f8eec49b0"
	strings:
		$s4 = "xl/worksheets/binaryIndex1.bin" fullword ascii
		$s8 = "xl/_rels/workbook.bin.rels " fullword ascii
		$s9 = "xl/drawings/drawing1.xml" fullword ascii
		$s13 = "xl/media/image2.jpg" fullword ascii
		$s15 = "xl/styles.bin" fullword ascii
		$s16 = "xl/worksheets/binaryIndex1.binPK" fullword ascii
		$s18 = "{lllllllllllllllll" fullword ascii
	condition:
		all of them
}

rule WoolenGoldfish_Sample_3 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		hash = "c727b8c43943986a888a0428ae7161ff001bf603"
	strings:
		$s0 = "xl/worksheets/_rels/sheet1.bin.rels" fullword ascii
		$s2 = "xl/drawings/_rels/drawing1.xml.rels" fullword ascii
		$s4 = "xl/worksheets/binaryIndex1.bin" fullword ascii
		$s5 = "xl/printerSettings/printerSettings1.binrb(e" fullword ascii
		$s6 = "xl/worksheets/sheet1.bin" fullword ascii
		$s8 = "xl/_rels/workbook.bin.rels " fullword ascii
		$s9 = "xl/drawings/drawing1.xml" fullword ascii
		$s12 = "xl/media/image2.jpg" fullword ascii
		$s15 = "xl/styles.bin" fullword ascii
		$s20 = "xl/sharedStrings.binl" fullword ascii
	condition:
		all of them
}

rule WoolenGoldfish_Generic_1 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		super_rule = 1
		hash0 = "5d334e0cb4ff58859e91f9e7f1c451ffdc7544c3"
		hash1 = "d5b2b30fe2d4759c199e3659d561a50f88a7fb2e"
		hash2 = "a42f1ad2360833baedd2d5f59354c4fc3820c475"
	strings:
		$x0 = "Users\\Wool3n.H4t\\"
		$x1 = "C-CPP\\CWoolger"
		$x2 = "NTSuser.exe" fullword wide

		$s1 = "107.6.181.116" fullword wide
		$s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
		$s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
		$s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
		$s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
		$s6 = "wlg.dat" fullword
		$s7 = "woolger" fullword wide
		$s8 = "[Enter]" fullword
		$s9 = "[Control]" fullword
	condition:
		( 1 of ($x*) and 2 of ($s*) ) or
		( 6 of ($s*) )
}

rule WoolenGoldfish_Generic_2 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		super_rule = 1
		hash0 = "0b0cdf47363fd27bccbfba6d47b842e44a365723"
		hash1 = "476489f75fed479f19bac02c79ce1befc62a6633"
		hash2 = "efd1c6a926095d36108177045db9ad21df926a6e"
	strings:
		$s1 = "; ;$;(;,;0;@;H;L;P;T;X;\\;`;d;h;l;x;0<4<" fullword
		$s2 = "= =9=E=R=Y=" fullword
		$s3 = "6#6)60666>6E6J6R6[6g6l6q6w6{6" fullword
		$s6 = "060?0E0R0\\0g0w0" fullword
		$s10 = "0044484<4@4D4H4L4P4T4`4" fullword
		$s11 = "1\"2(232?2T2Z2n2u2" fullword
		$s12 = "3\"31373@3L3Z3`3l3r3" fullword
		$s13 = ";\";5;@;F;L;Q;Z;w;};" fullword
	condition:
		all of them
}

rule WoolenGoldfish_Generic_3 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		super_rule = 1
		hash0 = "25d3688763e33eac1428622411d6dda1ec13dd43"
		hash1 = "8074ed48b99968f5d36a494cdeb9f80685beb0f5"
		hash2 = "e6964d467bd99e20bfef556d4ad663934407fd7b"
	strings:
		$s0 = "99:S:\\:" fullword
		$s1 = "; ;$;(;8;@;D;H;L;P;T;X;\\;`;d;p;0<4<" fullword
		$s2 = "4'4-484=4E4K4U4\\4p4w4}4" fullword
		$s3 = "=<>F>^>e>o>w>" fullword
		$s4 = ":c;m;1=C=U=r=" fullword
	condition:
		all of them
}

rule WoolenGoldfish_Generic_4 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		super_rule = 1
		hash0 = "fd8793ce4ca23988562794b098b9ed20754f8a90"
		hash1 = "729f9ce76f20822f48dac827c37024fe4ab8ff70"
		hash2 = "6e30d3ef2cd0856ff28adce4cc012853840f6440"
	strings:
		$s0 = "=$=.=A=c=" fullword
		$s4 = "1044484<4@4D4H4L4P4T4`4" fullword
		$s5 = "4!4*4G4M4X4]4e4k4u4|4" fullword
		$s11 = "0 090U0^0d0m0r0" fullword
		$s12 = "=;=G=M=p=w=" fullword
		$s20 = "5#505@5r5x5" fullword
	condition:
		all of them
}

rule WoolenGoldfish_Generic_5 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
		hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
		hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
		hash4 = "c1edf6e3a271cf06030cc46cbd90074488c05564"
	strings:
		$s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
	condition:
		all of them
}

rule WoolenGoldfish_Generic_6 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
		hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
	strings:
		$x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
		$x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
		$x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii

		$s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
		$s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
		$s2 = "Attempting to unlock uninitialized lock!" fullword ascii
		$s4 = "unable to load kernel32.dll" fullword ascii
		$s5 = "index.php?c=%S&r=%x" fullword wide
		$s6 = "%s len:%d " fullword ascii
		$s7 = "Encountered error sending syscall response to client" fullword ascii
		$s9 = "/info.dat" fullword ascii
		$s10 = "Error entering thread lock" fullword ascii
		$s11 = "Error exiting thread lock" fullword ascii
		$s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
	condition:
		( 1 of ($x*) ) or
		( 8 of ($s*) )
}

rule WoolenGoldfish_Generic_7 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		hash1 = "9579e65e3ae6f03ff7d362be05f9beca07a8b1b3"
		hash2 = "ad6c9b003285e01fc6a02148917e95c780c7d751"
	strings:
		$s0 = "xl/worksheets/_rels/sheet2.xml.rels" fullword ascii
		$s1 = "xl/worksheets/_rels/sheet1.xml.rels" fullword ascii
		$s4 = "xl/customProperty1.bin" fullword ascii
		$s5 = "xl/drawings/drawing1.xml" fullword ascii
		$s6 = "xl/worksheets/sheet1.xml" fullword ascii
		$s8 = "xl/_rels/workbook.xml.rels " fullword ascii
		$s13 = "xl/styles.xml" fullword ascii
		$s14 = "xl/workbook.xml" fullword ascii
		$s15 = "xl/drawings/drawing1.xmlPK" fullword ascii
		$s16 = "xl/worksheets/sheet1.xmlPK" fullword ascii
		$s20 = "xl/workbook.xmlPK" fullword ascii
	condition:
		all of them
}
