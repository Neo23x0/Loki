
rule ScanBox_Malware_Generic {
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		author = "Florian Roth"
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"
	strings:
		/* Sample 1 */
		$s0 = "http://142.91.76.134/p.dat" fullword ascii
		$s1 = "HttpDump 1.1" fullword ascii

		/* Sample 2 */
		$s3 = "SecureInput .exe" fullword wide
		$s4 = "http://extcitrix.we11point.com/vpn/index.php?ref=1" fullword ascii

		/* Sample 3 */
		$s5 = "%SystemRoot%\\System32\\svchost.exe -k msupdate" fullword ascii
		$s6 = "ServiceMaix" fullword ascii

		/* Certificate and Keywords */
		$x1 = "Management Support Team1" fullword ascii
		$x2 = "DTOPTOOLZ Co.,Ltd.0" fullword ascii
		$x3 = "SEOUL1" fullword ascii
	condition:
		( 1 of ($s*) and 2 of ($x*) ) or
		( 3 of ($x*) )
}
