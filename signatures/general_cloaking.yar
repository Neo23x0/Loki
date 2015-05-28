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
