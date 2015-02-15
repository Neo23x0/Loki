rule apt_regin_2011_32bit_stage1 {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin 32 bit stage 1 loaders"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$key1={331015EA261D38A7}
$key2={9145A98BA37617DE}
$key3={EF745F23AA67243D}
$mz="MZ"
condition:
($mz at 0) and any of ($key*) and filesize < 300000
}
rule apt_regin_rc5key {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin RC5 decryption keys"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$key1={73 23 1F 43 93 E1 9F 2F 99 0C 17 81 5C FF B4 01}
$key2={10 19 53 2A 11 ED A3 74 3F C3 72 3F 9D 94 3D 78}
condition:
any of ($key*)
}



rule apt_regin_vfs {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin VFSes"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$a1={00 02 00 08 00 08 03 F6 D7 F3 52}
$a2={00 10 F0 FF F0 FF 11 C7 7F E8 52}
$a3={00 04 00 10 00 10 03 C2 D3 1C 93}
$a4={00 04 00 10 C8 00 04 C8 93 06 D8}
condition:
($a1 at 0) or ($a2 at 0) or ($a3 at 0) or ($a4 at 0)
}
rule apt_regin_dispatcher_disp_dll {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin disp.dll dispatcher"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$mz="MZ"
 $string1="shit"
 $string2="disp.dll"
 $string3="255.255.255.255"
 $string4="StackWalk64"
 $string5="imagehlp.dll"
condition:
($mz at 0) and (all of ($string*))
}
rule apt_regin_2013_64bit_stage1 {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin 64 bit stage 1 loaders"
 version = "1.0"
 last_modified = "2014-11-18"
 filename="wshnetc.dll"
 md5="bddf5afbea2d0eed77f2ad4e9a4f044d"
 filename="wsharp.dll"
 md5="c053a0a3f1edcbbfc9b51bc640e808ce"
strings:
$mz="MZ"
$a1="PRIVHEAD"
$a2="\\\\.\\PhysicalDrive%d"
$a3="ZwDeviceIoControlFile"
condition:
($mz at 0) and (all of ($a*)) and filesize < 100000
}