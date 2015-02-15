rule zxshell_http_proxy_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "ZxHttpProxy" nocase
		$s2 = "(All IP Is Acceptable.)"
		$s3 = "(End Proxy Service.)"
		$s4 = "(View Server Info)"

	condition:
		#s1 > 1 and all of ($s*)

}