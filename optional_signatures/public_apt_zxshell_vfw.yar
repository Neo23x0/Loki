rule zxshell_vfw
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$mz = { 4d 5a }
		$plug = "zxplug" ascii
		$prefix1 = "[DeskTop]" ascii
		$prefix2 = "[RDT]" ascii
		$shsl = "ShareShell" ascii

	condition:
		( $mz at 0 ) and ((#plug > 2 and #shsl > 1) or (#prefix1 > 3) or (#prefix2 > 3)) 
}