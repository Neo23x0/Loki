rule alina
{
	meta:
		description = "This rule will detect a family of malware named Alina that is responsible for memory scraping and exfiltration (C&C). The malware targets track data on point of sale devices."
		author = "Josh Grunzweig"
		company = "Nuix"

	strings:
		$regex1 = "(((%?[Bb])[0-9]{13,19}\\^[A-Za-z\\s]{0,26}/[A-Za-z\\s]{0,26}\\^(1[2-9])(0[1-9]|1[0-2])[0-9\\s]{3,50}\\?)[; ]{1,3}([0-9]{13,19}=(1[2-9])(0[1-9]|1[0-2])[0-9]{3,50}\\?))"
		$regex2 = "([0-9]{13,19}=(1[2-9])(0[1-9]|1[0-2])[0-9]{3,50}\\?)"
		$regex3 = "((%?[Bb])[0-9]{13,19}\\^[A-Za-z\\s]{0,26}/[A-Za-z\\s]{0,26}\\^(1[2-9])(0[1-9]|1[0-2])[0-9\\s]{3,50}\\?)"

		$user_agent1 = /Alina v\d+\.\d+/ nocase
		$user_agent2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1 Spark v"

		$log1 = "{[!40!]}{[!4!]}{[!36!]}"
		$log2 = "{[!29!]}{[!32!]}"
		$log3 = "{[!30!]}{[!31!]}{[!4!]}"
		$log4 = "{[!2!]}{[!20!]}{[!21!]}"

		$blacklist1 = "explorer.exe"
		$blacklist2 = "chrome.exe"
		$blacklist3 = "firefox.exe"
		$blacklist4 = "iexplore.exe"
		$blacklist5 = "svchost.exe"
		$blacklist6 = "smss.exe"
		$blacklist7 = "crss.exe"
		$blacklist8 = "wininit.exe"
		$blacklist9 = "steam.exe"
		$blacklist10 = "devenv.exe"
		$blacklist11 = "thunderbird.exe"
		$blacklist12 = "skype.exe"
		$blacklist13 = "pidgin.exe"

	condition:
		(any of ($regex*)) or ((all of ($blacklist*)) and (any of ($user_agent*))) or (any of ($log*))
}