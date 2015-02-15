rule LURK0
{
    meta:
        description = "LURK0"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "2014-07-22"

    strings:    
        $header = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }
        // internal names
        $str1 = "Butterfly.dll"
        $str2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
        $str3 = "ETClientDLL"
        // dbx
        $str4 = "\\DbxUpdateET\\" wide
        $str5 = "\\DbxUpdateBT\\" wide
        $str6 = "\\DbxUpdate\\" wide
        // other folders
        $str7 = "\\Micet\\"
        // embedded file names
        $str8 = "IconCacheEt.dat" wide
        $str9 = "IconConfigEt.dat" wide
        $str10 = "ERXXXXXXX" wide
        $str11 = "111" wide
        $str12 = "ETUN" wide

    condition:
        $header and any of ($str*)
}