rule FakeMHTML
{
    meta:
        description = "FAKEM HTML Variant"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "2014-05-20"
    
    strings:
        // decryption loop
        $s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
        //mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
        $s2 = { C6 45 F? (3?|4?) }

    condition:
        $s1 and #s2 == 16

}