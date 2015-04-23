/*
	Core Impact Agent known from RocketKitten and WoolenGoldfish APT
*/


rule CoreImpact_sysdll_exe {
	meta:
		description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
		author = "Florian Roth"
		score = 70
		date = "27.12.2014"
		hash = "f89a4d4ae5cca6d69a5256c96111e707"
	strings:
		$s0 = "d:\\nightly\\sandbox_avg10_vc9_SP1_2011\\source\\avg10\\avg9_all_vs90\\bin\\Rele" ascii
		
		$x1 = "Mozilla/5.0" fullword ascii
		$x2 = "index.php?c=%s&r=%lx&u=1&t=%s" fullword ascii
		$x3 = "index.php?c=%s&r=%lx" fullword ascii
		$x4 = "index.php?c=%s&r=%x" fullword ascii
		$x5 = "127.0.0.1" fullword ascii
		$x6 = "/info.dat" fullword ascii
				
		$z1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide	
		$z2 = "Encountered error sending error message to client" fullword ascii
		$z3 = "Encountered error building error message to client" fullword ascii
		$z4 = "Attempting to unlock uninitialized lock!" fullword ascii
		$z5 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii
		$z6 = "select_event_get(): fd not found" fullword ascii
		$z7 = "Encountered error sending syscall response to client" fullword ascii
		$z8 = "GetProcAddress() error" fullword ascii
		$z9 = "Error entering thread lock" fullword ascii
		$z10 = "Error exiting thread lock" fullword ascii
		$z11 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
		$z12 = "event_add() failed for ev." fullword ascii
		$z13 = "Uh, oh, exit() failed" fullword ascii
		$z14 = "event_add() failed for ev." fullword ascii
		$z15 = "event_add() failed." fullword ascii
		$z16 = "needroot" fullword ascii
		$z17 = "./plugins/" fullword ascii	
	condition:
		$s0 or 
		all of ($x*) or 
		8 of ($z*)
}