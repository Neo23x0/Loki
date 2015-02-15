rule Gh0st1 
{
	meta:
		author = "Marcus Ruffin"
		yaraexchange = "Do Not Distribute"
		date = "2015-01"
		filetype = "PE"
		imphash = "81cf1dea5873d301c6baca589ca78828" 
		reference = "VirusTotal"
		
	strings:
	 
     		$mz = "MZ"
		$str1 = "Winsta0" nocase
      		$str2 = "Gh0st Update" nocase
      		$str3 = "Sunley.pdb" nocase
      		$str4 = "gh0st Rat 3.6" nocase
      		$str5 = "rasphone.pbk" nocase
           
			
	condition:
	
		$mz at 0 and 5 of ($str1,$str2,$str3,$str4,$str5)
            
            }