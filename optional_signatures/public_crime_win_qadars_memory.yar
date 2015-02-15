rule qadars : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Qadars - Mobile part. Maybe Perkele."
		version = "1.0" 
		filetype = "memory"
		ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

	strings:
		$cmd1 = "m?D"
		$cmd2 = "m?S"
		$cmd3 = "ALL"
		$cmd4 = "FILTER"
		$cmd5 = "NONE"
		$cmd6 = "KILL"
		$cmd7 = "CANCEL"
		$cmd8 = "SMS"
		$cmd9 = "DIVERT"
		$cmd10 = "MESS"
		$nofilter = "nofilter1111111"
		$botherderphonenumber1 = "+380678409210"

	condition:
		all of ($cmd*) or $nofilter or any of ($botherderphonenumber*)
}