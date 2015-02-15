//FBI wiper alert

rule unknown_wiper_error_strings{

meta: 
description = "unique custom error debug strings discovered in the wiper malware"

strings:

$IP1 = "203.131.222.102" fullword nocase

$IP2 = "217.96.33.164" fullword nocase

$IP3 = "88.53.215.64" fullword nocase

$MZ = "MZ"

condition:

$MZ at 0 and all of them

}