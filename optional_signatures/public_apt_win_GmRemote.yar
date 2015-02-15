rule GmRemote
{
    meta:
        description = "GmRemote"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "07-25-2014"
    
    strings:
        $rshared1 = "nView_DiskLoydb" wide
        $rshared2 = "nView_KeyLoydb" wide
        $rshared3 = "nView_skins" wide
        $rshared4 = "UsbLoydb" wide
        $rshared5 = "%sBurn%s" wide
        $rshared6 = "soul" wide
        $gmremote1 = "\x00x86_GmRemote.dll\x00"
        $gmremote2 = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
        $gmremote3 = "\x00GmShutPoint\x00"
        $gmremote4 = "\x00GmRecvPoint\x00"
        $gmremote5 = "\x00GmInitPoint\x00"
        $gmremote6 = "\x00GmVerPoint\x00"
        $gmremote7 = "\x00GmNumPoint\x00"
        $gmremote8 = "_Gt_Remote_" wide
        $gmremote9 = "%sBurn\\workdll.tmp" wide
    
    condition:
        any of ($rshared*) and any of ($gmremote*)
}