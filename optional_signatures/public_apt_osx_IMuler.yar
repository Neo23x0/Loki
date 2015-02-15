rule IMuler 
{
    meta:
        description = "IMuler"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-16"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
        $L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
        $L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
        $L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
        $L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }
        $str1 = "/cgi-mac/"
        $str2 = "xnocz1"
        $str3 = "checkvir.plist"
        $str4 = "/Users/apple/Documents/mac back"
        $str5 = "iMuler2"
        $str6 = "/Users/imac/Desktop/macback/"
        $str7 = "xntaskz.gz"
        $str8 = "2wmsetstatus.cgi"
        $str9 = "launch-0rp.dat"
        $str10 = "2wmupload.cgi"
        $str11 = "xntmpz"
        $str12 = "2wmrecvdata.cgi"
        $str13 = "xnorz6"
        $str14 = "2wmdelfile.cgi"
        $str15 = "/LanchAgents/checkvir"
        $str16 = "0PERA:%s"
        $str17 = "/tmp/Spotlight"
        $str18 = "/tmp/launch-ICS000"
        
    condition:
        all of ($L4*) or any of ($str*)
}
