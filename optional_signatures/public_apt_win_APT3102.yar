rule APT3102 
{
    meta:
        description = "3102"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
        
    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"
        
    condition:
       any of them
}
