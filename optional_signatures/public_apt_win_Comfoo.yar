rule Comfoo 
{
    meta:
        description = "Comfoo"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-20"
        
    strings:
        $resource = { 6A 6C 6A 59 55 E8 01 FA FF FF }
        $ = "fefj90"
        $ = "iamwaitingforu653890"
        $ = "watchevent29021803"
        $ = "THIS324NEWGAME"
        $ = "ms0ert.temp"
        $ = "\\mstemp.temp"
        
    condition:
       any of them
}