/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Emdivi_SFX {
	meta:
		description = "Detects Emdivi malware in SFX Archive"
		author = "Florian Roth @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		score = 70
		hash1 = "7a3c81b2b3c14b9cd913692347019887b607c54152b348d6d3ccd3ecfd406196"
		hash2 = "8c3df4e4549db3ce57fc1f7b1b2dfeedb7ba079f654861ca0b608cbfa1df0f6b"
	strings:
		$x1 = "Setup=unsecess.exe" fullword ascii
		$x2 = "Setup=leassnp.exe" fullword ascii

		$s1 = "&Enter password for the encrypted file:" fullword wide
		$s2 = ";The comment below contains SFX script commands" fullword ascii
		$s3 = "Path=%temp%" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 740KB and (1 of ($x*) and all of ($s*))
}

/* Super Rules ------------------------------------------------------------- */

rule Emdivi_Gen1 {
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		score = 80
		super_rule = 1
		hash1 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
		hash2 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
		hash3 = "6a331c4e654dd8ddaa2c69d260aa5f4f76f243df8b5019d62d4db5ae5c965662"
		hash4 = "90d07ea2bb80ed52b007f57d0d9a79430cd50174825c43d5746a16ee4f94ea86"
	strings:
		$x1 = "wmic nteventlog where filename=\"SecEvent\" call cleareventlog" fullword wide
		$s0 = "del %Temp%\\*.exe %Temp%\\*.dll %Temp%\\*.bat %Temp%\\*.ps1 %Temp%\\*.cmd /f /q" fullword wide
		$x3 = "userControl-v80.exe" fullword ascii

		$s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword wide
		$s2 = "http://www.msftncsi.com" fullword wide
		$s3 = "net use | find /i \"c$\"" fullword wide
		$s4 = " /del /y & " fullword wide
		$s5 = "\\auto.cfg" fullword wide
		$s6 = "/ncsi.txt" fullword wide
		$s7 = "Dcmd /c" fullword wide
		$s8 = "/PROXY" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule Emdivi_Gen2 {
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		super_rule = 1
		score = 80
		hash1 = "9a351885bf5f6fec466f30021088504d96e9db10309622ed198184294717add1"
		hash2 = "a5be7cb1f37030c9f9211c71e0fbe01dae19ff0e6560c5aab393621f18a7d012"
		hash3 = "9183abb9b639699cd2ad28d375febe1f34c14679b7638d1a79edb49d920524a4"
	strings:
		$s1 = "%TEMP%\\IELogs\\" fullword ascii
		$s2 = "MSPUB.EXE" fullword ascii
		$s3 = "%temp%\\" fullword ascii
		$s4 = "\\NOTEPAD.EXE" fullword ascii
		$s5 = "%4d-%02d-%02d %02d:%02d:%02d " fullword ascii
		$s6 = "INTERNET_OPEN_TYPE_PRECONFIG" fullword ascii
		$s7 = "%4d%02d%02d%02d%02d%02d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1300KB and 6 of them
}

rule Emdivi_Gen3 {
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		super_rule = 1
		score = 80
		hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
		hash2 = "a94bf485cebeda8e4b74bbe2c0a0567903a13c36b9bf60fab484a9b55207fe0d"
	strings:
		$x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword ascii

		$s2 = "\\Mozilla\\Firefox\\Profiles\\" fullword ascii
		$s4 = "\\auto.cfg" fullword ascii
		$s5 = "/ncsi.txt" fullword ascii
		$s6 = "/en-us/default.aspx" fullword ascii
		$s7 = "cmd /c" fullword ascii	
		$s9 = "APPDATA" fullword ascii /* Goodware String - occured 25 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 850KB and 
		(
			( $x1 and 1 of ($s*) ) or 
			( 4 of ($s*) )
		)
}

rule Emdivi_Gen4 {
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		super_rule = 1
		score = 80
		hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
		hash2 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
		hash3 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
		hash4 = "6a331c4e654dd8ddaa2c69d260aa5f4f76f243df8b5019d62d4db5ae5c965662"
		hash5 = "90d07ea2bb80ed52b007f57d0d9a79430cd50174825c43d5746a16ee4f94ea86"
		hash6 = "a94bf485cebeda8e4b74bbe2c0a0567903a13c36b9bf60fab484a9b55207fe0d"
	strings:
		$s1 = ".http_port\", " fullword wide
		$s2 = "UserAgent: " fullword ascii
		$s3 = "AUTH FAILED" fullword ascii
		$s4 = "INVALID FILE PATH" fullword ascii
		$s5 = ".autoconfig_url\", \"" fullword wide
		$s6 = "FAILED TO WRITE FILE" fullword ascii
		$s7 = ".proxy" fullword wide
		$s8 = "AuthType: " fullword ascii
		$s9 = ".no_proxies_on\", \"" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 853KB and all of them
}
