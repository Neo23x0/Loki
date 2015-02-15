rule Bangat 
{
    meta:
        description = "Bangat"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-10"
    
    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $code = { FE 4D ?? 8D 4? ?? 50 5? FF }
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc or $code
}