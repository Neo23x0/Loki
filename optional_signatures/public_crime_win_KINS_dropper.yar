rule KINS_dropper {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match protocol, process injects and windows exploit present in KINS dropper"
	strings:
		// Network protocol
		$n1 = "tid=%d&ta=%s-%x" fullword
		$n2 = "fid=%d" fullword
		$n3 = "%[^.].%[^(](%[^)])" fullword
		// Injects
		$i0 = "%s [%s %d] 77 %s"
		$i01 = "Global\\%s%x"
		$i1 = "Inject::InjectProcessByName()"
		$i2 = "Inject::CopyImageToProcess()"
		$i3 = "Inject::InjectProcess()"
		$i4 = "Inject::InjectImageToProcess()"
		$i5 = "Drop::InjectStartThread()"
		// UAC bypass
		$uac1 = "ExploitMS10_092"
		$uac2 = "\\globalroot\\systemroot\\system32\\tasks\\" ascii wide
		$uac3 = "<RunLevel>HighestAvailable</RunLevel>" ascii wide
	condition:
		2 of ($n*) and 2 of ($i*) and 2 of ($uac*)
}