rule zxshell_rootkit
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "the end!!" fullword
		$tcpstr0 = "TCPFilter_Attach Successfully."
		$tcpstr1 = "TCPFilter_Attach: TCPFilter_Detach Finished" fullword
		$tcpstr2 = "TCPFilter_Attach: Couldn't attach to TCP Device Object"
		$output1 = "filetype[NTFS] process:[%s] is scaning file[%ws][%ws]"
		$output2 = "file protect:%ws"

	condition:
		all of ($tcpstr*) and ($s1 or $output1 or $output2)
}
