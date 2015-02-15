rule LuckyCat 
{
    meta:
        description = "LuckyCat"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }
        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }
        $commonletters = { B? 63 B? 61 B? 73 B? 65 }
        $str1 = { 77 76 75 7B 7A 79 78 7F 7E 7D 7C 73 72 71 70 }
        $str2 = "%s\\~temp.vbs"
        $str3 = "count.php\x00"
        $str4 = /WMILINK=.*TrojanName=/
        $str5 = "d0908076343423d3456.tmp"
        $str6 = "cmd /c dir /s /a C:\\\\ >'+tmpfolder+'\\\\C.tmp"
        $str7 = "objIP.DNSHostName+'_'+objIP.MACAddress.split(':').join('')+'_'+addinf+'@')"
        
    condition:
       $xordecrypt or ($dll and $commonletters) or any of ($str*)
}