rule Havex
{
	meta:
			author = "Marcus J Ruffin"
			date = "2015-01"
			filetype = "PE"
			malwaretype = "Havex"
			reference = "VirusTotal"

	strings:

     	$mz = "MZ"
			$str1 = "Copyright (c) J.S.A.Kapp 94-96"
      $str2 = "cmd.exe /c"
      $str3 = "rwalton"

	condition:

			$mz at 0 and 2 of ($str1,$str2,$str3)
      }
