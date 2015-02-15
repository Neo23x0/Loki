rule dotfuscator : packer
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Dotfuscator"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0" 

	strings:
		$a = "Obfuscated with Dotfuscator"

	condition:
		$a
}