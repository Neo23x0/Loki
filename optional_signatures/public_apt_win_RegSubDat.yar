rule RegSubDat
{
    meta:
        description = "RegSubDat"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop
        $code1 = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
        // push then pop values
        $code2 = { 68 FF FF 7F 00 5? }
        $code3 = { 68 FF 7F 00 00 5? }
        $avg1 = "Button"
        $avg2 = "Allow"
        $avg3 = "Identity Protection"
        $avg4 = "Allow for all"
        $avg5 = "AVG Firewall Asks For Confirmation"
        $mutex = "0x1A7B4C9F"
        
    condition:
       all of ($code*) or all of ($avg*) or $mutex
}
