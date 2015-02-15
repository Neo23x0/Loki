rule ice_ix_12xy : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "ICE-IX 1.2.x.y trojan banker"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 
	
	strings:
		$regexp1= /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
		$a = "bn1="
		$b = "&sk1="
		$c = "mario"								//HardDrive GUID artifact
		$d = "FIXME"
		$e = "RFB 003.003"							//VNC artifact
		$ggurl = "http://www.google.com/webhp"

	condition:
		$regexp1 or ($a and $b) or all of ($c,$d,$e,$ggurl) 
}