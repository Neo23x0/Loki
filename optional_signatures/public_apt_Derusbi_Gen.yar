rule APT_Derusbi_Gen
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$2 = "273ce6-b29f-90d618c0" wide ascii
	$A = "Ace123dx" fullword wide ascii
	$A1 = "Ace123dxl!" fullword wide ascii
	$A2 = "Ace123dx!@#x" fullword wide ascii
	$C = "/Catelog/login1.asp" wide ascii
	$DF = "~DFTMP$$$$$.1" wide ascii
	$G = "GET /Query.asp?loginid=" wide ascii
	$L = "LoadConfigFromReg failded" wide ascii
	$L1 = "LoadConfigFromBuildin success" wide ascii
	$ph = "/photoe/photo.asp HTTP" wide ascii
	$PO = "POST /photos/photo.asp" wide ascii
	$PC = "PCC_IDENT" wide ascii
condition:
	any of them
}