rule Vidgrab
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        $str1 = "IDI_ICON5" wide ascii
        $str2 = "starter.exe"
        $str3 = "wmifw.exe"
        $str4 = "Software\\rar"
        $str5 = "tmp092.tmp"
        $str6 = "temp1.exe"
        
    condition:
       ($divbyzero and $xorloop and $junk) or 3 of ($str*)
}