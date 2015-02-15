rule chicken_dos{
  meta:
    author = "Jason Jones <jasonjones@arbor.net>"
    description= "Win32-variant of Chicken ident for both dropper and dropped file"
  strings:
    $pdb1 = "\\Chicken\\Release\\svchost.pdb"
    $pdb2 = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"
    $str2 = "fake.cf"
    $str3 = "8.8.8.8"
    $str4 = "Processor(%d)\\"
    $str5 = "DbProtectSupport"
    $str1 = "dm1712/`jvpnpkte/bpl"
    $str6 = "InstallService NPF %d"
    $str7 = "68961"
    $str8 = "InstallService DbProtectSupport %d"
    $str9 = "C:\\Program Files\\DbProtectSupport\\npf.sys"
  condition:
    ($pdb1 or $pdb2) and 5 of ($str*)
}

rule chicken_dos_linux {
  meta:
    author = "Jason Jones <jasonjones@arbor.net>"
    description= "Linux-variant of Chicken ident for both dropper and dropped file"
  strings:
    $cfg = "fake.cfg"
    $file1 = "ThreadAttack.cpp"
    $file2 = "Fake.cpp"
    $str1 = "dns_array"
    $str2 = "DomainRandEx"
    $str3 = "cpu %llu %llu %llu %llu"
    $str4 = "[ %02d.%02d %02d:%02d:%02d.%03ld ] [%lu] [%s] %s" ascii
  condition:
    $cfg and all of ($file*) and 3 of ($str*)
}