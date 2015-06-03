
rule APT_Malware_CommentCrew_MiniASP {
	meta:
		description = "CommentCrew Malware MiniASP APT"
		author = "Florian Roth"
		reference = "VT Analysis"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "0af4360a5ae54d789a8814bf7791d5c77136d625"
		hash1 = "777bf8def279942a25750feffc11d8a36cc0acf9"
		hash2 = "173f20b126cb57fc8ab04d01ae223071e2345f97"
	strings:
		$x1 = "\\MiniAsp4\\Release\\MiniAsp.pdb" ascii /* score: '19.02' */
		$x2 = "run http://%s/logo.png setup.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.02' */
		$x3 = "d:\\command.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */

		$z1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR " ascii /* PEStudio Blacklist: strings */ /* score: '24.02' */
		$z2 = "Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.03' */
		$z3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC" ascii /* PEStudio Blacklist: agent */ /* score: '32.03' */
		
		$s1 = "http://%s/device_command.asp?device_id=%s&cv=%s&command=%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.02' */
		$s2 = "kill process error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.04' */
		$s3 = "kill process success!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.04' */
		$s4 = "pickup command error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.04' */
		$s5 = "http://%s/record.asp?device_t=%s&key=%s&device_id=%s&cv=%s&result=%s" fullword ascii /* score: '20.01' */
		$s6 = "no command" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.05' */
		$s7 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii /* score: '19.02' */
		$s8 = "command is null!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.05' */
		$s9 = "pickup command Ok!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.04' */
		$s10 = "http://%s/result_%s.htm" fullword ascii /* score: '18.01' */
	condition:
		uint16(0) == 0x5a4d and 
		( 1 of ($x*) ) or 
		( all of ($z*) ) or 
		( 8 of ($s*) )
}