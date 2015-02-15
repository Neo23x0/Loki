rule rtf_Kaba_jDoe
{
meta:
	author = "@patrickrolsen"
	maltype = "APT.Kaba"
	filetype = "RTF"
	version = "0.1"
	description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
	date = "2013-12-10"
strings:
  	$magic1 = { 7b 5c 72 74 30 31 } // {\rt01
  	$magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
  	$magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
  	$author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
  	$author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
	$string1 = { 44 30 [16] 43 46 [23] 31 31 45 }
condition:
  	($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
} 

rule rtf_yahoo_ken
{
meta:
	author = "@patrickrolsen"
	maltype = "Yahoo Ken"
	filetype = "RTF"
	version = "0.1"
	description = "Test rule"
	date = "2013-12-14"
strings:
	$magic1 = { 7b 5c 72 74 30 31 } // {\rt01
	$magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
	$magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
	$author1 = { 79 61 68 6f 6f 20 6b 65 63 } // "yahoo ken"
condition:
	($magic1 or $magic2 or $magic3 at 0) and $author1
} 

rule Backdoor_APT_Mongall
{
meta:
	author = "@patrickrolsen"
	maltype = "Backdoor.APT.Mongall"
	version = "0.1"
	reference = "fd69a799e21ccb308531ce6056944842" 
	date = "01/04/2014"
strings:
	$author  = "author user"
	$title   = "title Vjkygdjdtyuj" nocase
	$comp    = "company ooo"
	$cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
	$passwd  = "password 00000000"
condition:
        all of them
}

rule tran_duy_linh
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.1"
	reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
	date = "2013-12-12"
strings:
	$magic = {D0 CF 11 E0} //DOCFILE0
	$string1 = "Tran Duy Linh" fullword
	$string2 = "DLC Corporation" fullword
condition:
    $magic at 0 and all of ($string*)
}