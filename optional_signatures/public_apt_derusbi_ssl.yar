rule derusbi_ssl
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$live = "login.live.com"
		$get = {0047455420687474703A2F2F00255B5E3A5D3A256400}

	condition:
		all of them

}