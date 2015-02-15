rule zxshell_zxsocksproxy_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "ZXSocksProxy" nocase
		$s2 = "ZXSocksProxy Service Isn't Running"
		$s3 = "(View SocksProxy Server Info)"
		$s4 = "Try to change a Port and then try again."
	condition:
		#s1 > 5 and all of ($s*)
}