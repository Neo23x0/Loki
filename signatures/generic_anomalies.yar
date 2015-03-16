
rule Embedded_EXE_Cloaking {
        meta:
                description = "Detects an embedded executable in a non-executable file"
                author = "Florian Roth"
                date = "2015/02/27"
                score = 80
        strings:
                $noex_png = { 89 50 4E 47 }
                $noex_pdf = { 25 50 44 46 }
                $noex_rtf = { 7B 5C 72 74 66 31 }
                $noex_jpg = { FF D8 FF E0 }
                $noex_gif = { 47 49 46 38 }
                $mz  = { 4D 5A }
                $a1 = "This program cannot be run in DOS mode"
                $a2 = "This program must be run under Win32"
        condition:
                (
                        ( $noex_png at 0 ) or
                        ( $noex_pdf at 0 ) or
                        ( $noex_rtf at 0 ) or
                        ( $noex_jpg at 0 ) or
                        ( $noex_gif at 0 )
                )
                and
                for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule Cloaked_as_JPG {
        meta:
                description = "Detects a cloaked file as JPG"
                author = "Florian Roth (eval section from Didier Stevens)"
                date = "2015/02/29"
                score = 70
        strings:
                $ext = "extension: .jpg"
        condition:
                $ext and uint16be(0x00) != 0xFFD8
}

rule GIFCloaked_Webshell {
	meta:
		description = "Detects a webshell that cloakes itself with GIF header(s) - Based on Dark Security Team Webshell"
		author = "Florian Roth"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		score = 50
	strings:
		$magic = "GIF"
		$s0 = "input type"
		$s1 = "<%eval request"
		$s2 = "<%eval(Request.Item["
		$s3 = "LANGUAGE='VBScript'"
	condition:
		( $magic at 0 ) and ( 1 of ($s*) )
}
