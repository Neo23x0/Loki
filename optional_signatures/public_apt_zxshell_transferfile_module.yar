rule zxshell_transferfile_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$cmd = "TransFile"
		$s1 = "put IP port user pass localfile remotefile"
		$s2 = "get URL SaveAs"
		$s3 = "Transfer successful: %d bytes in %d millisecond."
	condition:
		#cmd > 3 and all of ($s*) 
}