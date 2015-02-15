rule XtremeRAT
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-09"
    
    strings:
        // call; fstp st
        $code1 = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $code2 = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
        $str1 = "dqsaazere"
        $str2 = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       all of ($code*) or any of ($str*)
}