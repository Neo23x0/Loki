rule CrowdStrike_Shamoon_DroppedFile
{ meta:
description = "Rule to detect Shamoon malware."
strings:
$testn123 = "test123" wide
$testn456 = "test456" wide
$testn789 = "test789" wide
$testdomain = "testdomain.com" wide
$pingcmd = "ping -n 30 127.0.0.1 >nul" wide
condition:
(any of ($testn*) or $pingcmd) and $testdomain
}