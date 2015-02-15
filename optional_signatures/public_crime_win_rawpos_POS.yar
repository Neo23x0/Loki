rule rawpos
{
	meta:
		description = "RAW.Pos is a fairly prevalent memory scraper that has been seen on a number of cases"
		category = "Point of Sale"
		author = "Josh Grunzweig"

	strings:
		$_main = { 55 8B EC 81 C4 00 F8 FF FF 53 56 57 8B 75 0C 6A 00 E8 0A 09 00 00 59 6A ?? E8 ?? B0 00 00 59 FF 36 68 ?? ?? ?? ?? 8D 85 00 F8 FF FF 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 95 00 F8 FF FF 52 E8 ?? B0 00 00 59 6A 00 E8 ?? 9D 00 00 }

		$string1 = "cmd /C start %s"
		$string2 = "pid-%s.dmp"
		$string3 = "Dumping private memory for pid %s to %s.dmp..."
		$string4 = "Process Memory Dumper"
		$string5 = "Made By: DiabloHorn (Proud Member of: KD-Team)"
		$string6 = "Found track data at %s with PID %d!"
		$string7 = "memdump\\data-%s-%d.dmp"

	condition:
		$_main or all of ($string*)
}

rule rawpos_service
{
	meta:
		description = "RAW.Pos is a fairly prevalent memory scraper that has been seen on a number of cases. This detection discovers the service component to this malware family."
		category = "Point of Sale"
		author = "Josh Grunzweig"

	strings:
		$string1 = "install"
		$string2 = "remove"
		$string3 = "debug"
		$string4 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s"
		$string5 = "\\\\.\\pipe\\susrv"

		$cmd = /start \/min \w+\.exe/

	condition:
		all of ($string*) and #cmd > 1
}