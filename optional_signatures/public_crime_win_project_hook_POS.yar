rule pos_malware_project_hook
{
meta:
	author = "@patrickrolsen"
	maltype = "Project Hook"
	version = "0.1"
	description = "Table 1 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
	reference = "759154d20849a25315c4970fe37eac59"
	date = "12/30/2013"
strings:
	$magic = { 4D 5A } // MZ Header
	$string1 = "CallImage.exe"
	$string2 = "BurpSwim"
	$string3 = "Work\\Project\\Load"
	$string4 = "WortHisnal"
    
condition:
	($magic at 0) and all of ($string*)
}
