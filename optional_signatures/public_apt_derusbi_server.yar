rule Derusbi_Server 
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$uuid = "{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" wide ascii
		$infectionID1 = "-%s-%03d"
		$infectionID2 = "-%03d"
		$other = "ZwLoadDriver"
	condition:
		$uuid or ($infectionID1 and $infectionID2 and $other)
}