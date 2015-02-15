rule MacControl
{
    meta:
        description = "MacControl"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-17"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        $str1 = "HTTPHeadGet"
        $str2 = "/Library/launched"
        $str3 = "My connect error with no ip!"
        $str4 = "Send File is Failed"
        $str5 = "****************************You Have got it!****************************"
        
    condition:
        all of ($L4*) or $GEThgif or any of ($str*)
}