rule NSFree
{
    meta:
        description = "NSFree"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-24"
    
    strings:
        // push vars then look for MZ
        $code1 = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $code2 = { 90 90 90 90 81 3F 50 45 00 00 }
        $str1 = "\\MicNS\\" nocase
        $str2 = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $str3 = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       all of ($code*) or any of ($str*)
}