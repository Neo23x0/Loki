rule Mirage
{
    meta:
        description = "Mirage"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
        any of them
}