rule zxshell_pluginmanager
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$a1 ="%d plug-ins you add the command" fullword
		$a2 = "Error, the plugin is not loaded." fullword
		$a3 = "Plug-in added successfully. %s" fullword
		$b1 = "not export zxMain func."
		$b2 = "cmd name exist, please use other."
		$b3 = "SYSTEM\\CurrentControlSet\\Control\\zxplug"
		$cmd = "zxplug"

	condition:
		#cmd > 3 and (all of ($a*) or all of ($b*))
} 
