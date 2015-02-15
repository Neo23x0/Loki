rule jRAT_conf : rat 
{
	meta:
		description = "jRAT configuration" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-10-11"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py" 
		ref2 = "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html" 

	strings:
		$a = /port=[0-9]{1,5}SPLIT/ 

	condition: 
		$a
}