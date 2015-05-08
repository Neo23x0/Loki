/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-05-05
	Identifier: CarbonGrabber
*/

/* Rule Set ----------------------------------------------------------------- */

rule Rombertik_CarbonGrabber {
	meta:
		description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
		hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
		hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c" 
		hash4 = "98223d4ec272d3a631498b621618d875dd32161d" 	
	strings:
		$x1 = "ZwGetWriteWatch" fullword ascii
		$x2 = "OutputDebugStringA" fullword ascii
		$x3 = "malwar" fullword ascii
		$x4 = "sampl" fullword ascii
		$x5 = "viru" fullword ascii
		$x6 = "sandb" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5MB and all of them
}

rule Rombertik_CarbonGrabber_Panel_InstallScript {
	meta:
		description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"
	strings:
		$s0 = "$insert = \"INSERT INTO `logs` (`id`, `ip`, `name`, `host`, `post`, `time`, `bro" ascii
		$s3 = "`post` text NOT NULL," fullword ascii
		$s4 = "`host` text NOT NULL," fullword ascii
		$s5 = ") ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;\" ;" fullword ascii
		$s6 = "$db->exec($columns); //or die(print_r($db->errorInfo(), true));;" fullword ascii
		$s9 = "$db->exec($insert);" fullword ascii
		$s10 = "`browser` text NOT NULL," fullword ascii
		$s13 = "`ip` text NOT NULL," fullword ascii
	condition:
		filesize < 3KB and all of them
}

rule Rombertik_CarbonGrabber_Panel {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Panel - file index.php"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "e6e9e4fc3772ff33bbeeda51f217e9149db60082"
	strings:
		$s0 = "echo '<meta http-equiv=\"refresh\" content=\"0;url=index.php?a=login\">';" fullword ascii
		$s1 = "echo '<meta http-equiv=\"refresh\" content=\"2;url='.$website.'/index.php?a=login" ascii
		$s2 = "header(\"location: $website/index.php?a=login\");" fullword ascii
		$s3 = "$insertLogSQL -> execute(array(':id' => NULL, ':ip' => $ip, ':name' => $name, ':" ascii
		$s16 = "if($_POST['username'] == $username && $_POST['password'] == $password){" fullword ascii
		$s17 = "$SQL = $db -> prepare(\"TRUNCATE TABLE `logs`\");" fullword ascii
	condition:
		filesize < 46KB and all of them
}

rule Rombertik_CarbonGrabber_Builder {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
	strings:
		$s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
		$s1 = "Host(www.panel.com): " fullword ascii
		$s2 = "Path(/form/index.php?a=insert): " fullword ascii
		$s3 = "FileName: " fullword ascii
		$s4 = "~Rich8" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 35KB and all of them
}

rule Rombertik_CarbonGrabber_Builder_Server {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder Server - file Server.exe"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "895fab8d55882eac51d4b27a188aa67205ff0ae5"
	strings:
		$s0 = "C:\\WINDOWS\\system32\\svchost.exe" fullword ascii
		$s3 = "Software\\Microsoft\\Windows\\Currentversion\\RunOnce" fullword ascii
		$s4 = "chrome.exe" fullword ascii
		$s5 = "firefox.exe" fullword ascii
		$s6 = "chrome.dll" fullword ascii
		$s7 = "@KERNEL32.DLL" fullword wide
		$s8 = "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome" ascii
		$s10 = "&post=" fullword ascii
		$s11 = "&host=" fullword ascii
		$s12 = "Ws2_32.dll" fullword ascii
		$s16 = "&browser=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 8 of them
}
