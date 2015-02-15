rule Olyx
{
    meta:
        description = "Olyx"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
        $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }
        $ = "/Applications/Automator.app/Contents/MacOS/DockLight"
       
    condition:
        any of them
}