rule zxshell_shareshell_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$cmd = "ShareShell"
		$s1 = "Shared a shell to %s:%s Successfully."
		$s2 = "ShareShell 1.1.1.1 99"
	condition:
		#cmd > 1 and all of ($s*) 
} 