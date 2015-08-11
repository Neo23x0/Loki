
rule Flash_CVE_2015_5119_APT3 {
    meta:
        description = "Exploit Sample CVE-2015-5119"
        author = "Florian Roth"
        score = 70
        yaraexchange = "No distribution without author's consent" 
        date = "2015-08-01"
    strings:
        $s0 = "HT_exploit" fullword ascii
        $s1 = "HT_Exploit" fullword ascii
        $s2 = "flash_exploit_" ascii
        $s3 = "exp1_fla/MainTimeline" ascii fullword
        $s4 = "exp2_fla/MainTimeline" ascii fullword
        $s5 = "_shellcode_32" fullword ascii
        $s6 = "todo: unknown 32-bit target" fullword ascii 
    condition:
        uint16(0) == 0x5746 and 1 of them
}