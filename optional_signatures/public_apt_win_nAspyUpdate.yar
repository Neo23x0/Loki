rule nAspyUpdate
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop in dropper
        $ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }
        $ = "\\httpclient.txt"
        $ = "password <=14"
        $ = "/%ldn.txt"
        $ = "Kill You\x00"
        
    condition:
        any of them
}