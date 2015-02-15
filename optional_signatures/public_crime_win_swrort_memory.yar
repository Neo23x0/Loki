rule swrort : rat
{
	meta:
		description = "Trojan:Win32/Swrort / Downloader"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-06-22"
		filetype = "memory"
		version = "1.0" 

	strings:
		$path = "c:\\code\\httppump\\inner\\objchk_wxp_x86\\i386\\i.pdb"

	condition:
		all of them
}