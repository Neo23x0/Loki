rule EXE_cloaked_as_TXT {
	meta:
		description = "Executable with TXT extension"
		author = "Florian Roth"
	condition:
		uint16(0) == 0x5a4d 					// Executable
		and filename matches /\.txt$/is   // TXT extension (case insensitive)
}

rule EXE_extension_cloaking {
	meta:
		description = "Executable showing different extension (Windows default 'hide known extension')"
		author = "Florian Roth"
	condition:
		filename matches /\.txt\.exe$/is or	// Special file extensions
		filename matches /\.pdf\.exe$/is		// Special file extensions
}

rule Cloaked_RAR_File {
	meta:
		description = "RAR file cloaked by a different extension"
		author = "Florian Roth"
	condition:
		uint32be(0) == 0x52617221			// RAR File Magic Header
		and not filename matches /\.rar$/is	// not the .RAR extension
		and not filepath contains "Recycle" // not a deleted RAR file in recycler
}

rule Office_AutoOpen_Macro {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 60
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		uint32be(0) == 0xd0cf11e0 and all of ($s*) and filesize < 300000
}