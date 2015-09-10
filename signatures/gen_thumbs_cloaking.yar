rule Exe_Cloaked_as_ThumbsDb
    {
    meta:
        description = "Detects an executable cloaked as thumbs.db - Malware"
        date = "2014-07-18"
        author = "Florian Roth"
        score = 50
    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}