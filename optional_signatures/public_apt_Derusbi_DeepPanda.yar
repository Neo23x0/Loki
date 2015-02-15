rule APT_Derusbi_DeepPanda
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"
strings:
	$D = "Dom4!nUserP4ss" wide ascii
condition:
	$D
}