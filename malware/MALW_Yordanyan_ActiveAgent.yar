
rule yordanyan_activeagent {
	meta:
		description = "Memory string yara for Yordanyan ActiveAgent"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection"
		reference2 = "ETPRO TROJAN Win32.ActiveAgent CnC Create"
		date = "2018-10-04"
		maltype = "Botnet"
		filetype = "memory"

	strings:
		// the wide strings are 16bit bigendian strings in memory. strings -e b memdump.file
		$s01 = "I'm KeepRunner!" wide
		$s02 = "I'm Updater!" wide
		$s03 = "Starting Download..." wide
		$s04 = "Download Complete!" wide
		$s05 = "Running New Agent and terminating updater!" wide
		$s06 = "Can't Run downloaded file!" wide
		$s07 = "Retrying download and run!" wide
		$s08 = "Can't init Client." wide
		$s09 = "Client initialised -" wide
		$s10 = "Client not found!" wide
		$s11 = "Client signed." wide
		$s12 = "GetClientData" wide
		$s13 = "&counter=" wide
		$s14 = "&agent_file_version=" wide
		$s15 = "&agent_id=" wide
		$s16 = "mac_address=" wide
		$s17 = "Getting Attachments" wide
		$s18 = "public_name" wide
		$s19 = "Yor agent id =" wide
		$s20 = "Yor agent version =" wide
		$s21 = "Last agent version =" wide
		$s22 = "Agent is last version." wide
		$s23 = "Updating Agent" wide
		$s24 = "Terminating RunKeeper" wide
		$s25 = "Terminating RunKeeper: Done" wide
		$s26 = "ActiveAgent" ascii
		$s27 = "public_name" ascii

	condition:
		15 of them

}


