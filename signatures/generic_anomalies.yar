
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

rule Embedded_Webshell_in_Image {
        meta:
                description = "Detects an embedded web shell in an image file"
                author = "Florian Roth (eval section from Didier Stevens)"
                date = "2015/02/29"
        strings:               
                $langA1 = "<%"
                $langA2 = "%>"
                $langB1 = "<?"
                $langB2 = "?>"
                
                $key1 = "request" nocase
                $key2 = " LANGUAGE" fullword
                $key3 = "VBScript." fullword
                $key4 = "Response."
                $key5 = "<web-app>"
                $key6 = "jsp:scriptlet" fullword
                $key7 = "$_SESSION" fullword
                $key8 = "$_POST" fullword
                $key9 = "$_GET" fullword

                $eval = /\beval\s*\(/
        condition:
                (
                        uint32be(0x00) == 0x89504E47 or // PNG
                        uint16be(0x00) == 0xFFD8 or // JPEG
                        uint32be(0x00) == 0x47494638 // GIF
                )
                and 
                ( 
                        $eval or 
                        ( ( all of ($langA*) or all of ($langB*) ) and 1 of ($key*) )
                )     
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