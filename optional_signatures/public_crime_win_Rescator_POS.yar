rule pdb_strings_Rescator
{
meta:
	author = "@patrickrolsen"
	maltype = "N/A Threat Intel..."
	version = "0.2"
	description = "Rescator PDB strings within binaries"
	date = "01/03/2014"
strings:
	$magic = { 4D 5A } // MZ Header
	$pdb1 = "\\Projects\\Rescator" nocase
condition:
	($magic at 0) and $pdb1
}