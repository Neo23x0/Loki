/*
BlackShades Signature
*/

rule BlackShades : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="26/06/2013"
		description="BlackShades Server"
		
	strings:
		$signature1={62 73 73 5F 73 65 72 76 65 72}
		$signature2={43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
		$signature3={6D 6F 64 49 6E 6A 50 45}
		
	condition:
		$signature1 and $signature2 and $signature3
}