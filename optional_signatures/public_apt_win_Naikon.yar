rule Naikon
{
    meta:
        description = "Naikon"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $decr1 = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $decr2 = { 35 5A 01 00 00} // xor eax, 15ah
        $decr3 = { 81 C2 7F 14 06 00 } // add edx, 6147fh
        $str1 = "NOKIAN95/WEB"
        $str2 = "/tag=info&id=15"
        $str3 = "skg(3)=&3.2d_u1"
        $str4 = "\\Temp\\iExplorer.exe"
        $str5 = "\\Temp\\\"TSG\""
        
    condition:
       all of ($decr*) or any of ($str*)
}
