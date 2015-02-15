rule PubSab
{
    meta:
        description = "PubSab"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }
        $ = "_deamon_init"
        $ = "com.apple.PubSabAgent"
        $ = "/tmp/screen.jpeg"
       
    condition:
        any of them
}