rule zxshell_variant1
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"


	strings:
		$prefix1 = "[RDT] " ascii
		$prefix2 = "[DeskTop] " ascii
		$s1 = "IsThatMyMaster Error" ascii
		$s2 = "exec cmd failed :(" ascii
		$bs1 = {ff 15 70 50 00 10}
		condition:
			(#prefix1 > 3 or #prefix2 > 1) and (all of ($s*) or #bs1 > 1)
}
