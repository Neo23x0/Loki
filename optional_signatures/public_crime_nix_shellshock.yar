rule shellshock_generic

{
meta:
author="Adam Burt"
strings:
$starter = "() { "
$alt1 = "(a)=>"
$alt2 = ":; } ;"
$att1 = "HOLD Flooding"
$att2 = "JUNK Flooding"
$att4 = "PONG!"
$att5 = "/bin/busybox"
$att6 = "SCANNER"
condition:
( $starter and any of ($alt*) ) or ( all of ($att*) )
}