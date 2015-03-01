
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
                author = "Florian Roth"
                date = "2015/02/28"
                score = 80
        strings:
                $noex_png = { 89 50 4E 47 }
                $noex_jpg = { FF D8 FF E0 }
                $noex_gif = { 47 49 46 38 }
                
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
        condition:
                (
                        ( $noex_png at 0 ) or
                        ( $noex_jpg at 0 ) or
                        ( $noex_gif at 0 )
                )
                and ( all of ($langA*) or all of ($langB*) ) 
                and 1 of ($key*)
                
}
