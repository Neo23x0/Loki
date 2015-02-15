rule zxshell_portscan_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "================Start Scaning================" 
		$s2 = "================End================" 
		$s3 = "TCP Port MultiScanner"

	condition:
		all of them

}