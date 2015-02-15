rule APT_Hikit_msrv
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$m = {6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}
condition:
	any of them
}