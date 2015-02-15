rule pos_memory_scrapper
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware Memory Scraper"
	version = "0.2"
	description = "POS Memory Scraper"
	reference = "7f9cdc380eeed16eaab3e48d59f271aa"
	// http://www.xylibox.com/2013/05/dump-memory-grabber-blackpos.html"
	date = "01/03/2014"
strings:
	$magic = { 4D 5A } // MZ Header
	$string1 = "kartoxa" nocase
	$string2 = "CC2 region:"
	$string3 = "CC memregion:"
	$string4 = "target pid:"
	$string5 = "scan all processes:"
	$string6 = "<pid> <PATTERN>"
	$string7 = "KAPTOXA" nocase
condition:
	($magic at 0) and all of ($string*)
}