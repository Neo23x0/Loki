rule pos_malwre_dexter_stardust
{
meta:
	author = "@patrickrolsen"
	maltype = "Dexter Malware - StarDust Variant"
	version = "0.1"
	description = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
	reference = "16b596de4c0e4d2acdfdd6632c80c070, 2afaa709ef5260184cbda8b521b076e1, and e3dd1dc82ddcfaf410372ae7e6b2f658"
	date = "12/30/2013"
strings:
	$magic = { 4D 5A } // MZ Header
	$string1 = "ceh_3\\.\\ceh_4\\..\\ceh_6"
	$string2 = "Yatoed3fe3rex23030am39497403"
	$string3 = "Poo7lo276670173quai16568unto1828Oleo9eds96006nosysump7hove19"
	$string4 = "CommonFile.exe"
condition:
	($magic at 0) and all of ($string*)
}