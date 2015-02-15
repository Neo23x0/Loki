rule Remote
{
    meta:
        description = "Remote"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "07-25-2014"
    
    strings:
        $rshared1 = "nView_DiskLoydb" wide
        $rshared2 = "nView_KeyLoydb" wide
        $rshared3 = "nView_skins" wide
        $rshared4 = "UsbLoydb" wide
        $rshared5 = "%sBurn%s" wide
        $rshared6 = "soul" wide
        $remote1 = "\x00Remote.dll\x00"
        $remote2 = "\x00CGm_PlugBase::"
        $remote3 = "\x00ServiceMain\x00_K_H_K_UH\x00"
        $remote4 = "\x00_Remote_\x00" wide

    condition:
        any of ($rshared*) and any of ($remote*)
}