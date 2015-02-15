rule zxshell_zxnc_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "ZXNC"
		$s2 = "listen mode, for inbound connects"
		$s3 = "(while in the ZXNC mode type this option to quit it.)"

	condition:
		all of them

}