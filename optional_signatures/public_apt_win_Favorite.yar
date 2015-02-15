rule Favorite 
{
    meta:
        description = "Favorite"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-24"
    
    strings:
        // standard string hiding
        $code1 = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $code2 = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($code*) or any of ($string*) or all of ($file*)
}