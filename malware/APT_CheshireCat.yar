/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-08
	Identifier: Cheshire Cat
	Version: 0.1 
*/

/* Rule Set ----------------------------------------------------------------- */

rule CheshireCat_Sample2 {
	meta:
		description = "Auto-generated rule - file dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		score = 70
		hash = "dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
	strings:
		$s0 = "mpgvwr32.dll" fullword ascii
		$s1 = "Unexpected failure of wait! (%d)" fullword ascii
		$s2 = "\"%s\" /e%d /p%s" fullword ascii
		$s4 = "error in params!" fullword ascii
		$s5 = "sscanf" fullword ascii
		$s6 = "<>Param : 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of ($s*)
}

/* Generic Rules ----------------------------------------------------------- */
/* Gen1 is more exact than Gen2 - until now I had no FPs with Gen2 */

rule CheshireCat_Gen1 {
	meta:
		description = "Auto-generated rule - file ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		super_rule = 1
		score = 90
		hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
		hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"
	strings:
		$x1 = "CAPESPN.DLL" fullword wide
		$x2 = "WINF.DLL" fullword wide
		$x3 = "NCFG.DLL" fullword wide
		$x4 = "msgrthlp.dll" fullword wide
		$x5 = "Local\\{c0d9770c-9841-430d-b6e3-575dac8a8ebf}" fullword ascii
		$x6 = "Local\\{1ef9f94a-5664-48a6-b6e8-c3748db459b4}" fullword ascii

		$a1 = "Interface\\%s\\info" fullword ascii
		$a2 = "Interface\\%s\\info\\%s" fullword ascii
		$a3 = "CLSID\\%s\\info\\%s" fullword ascii
		$a4 = "CLSID\\%s\\info" fullword ascii

		$b1 = "Windows Shell Icon Handler" fullword wide
		$b2 = "Microsoft Shell Icon Handler" fullword wide

		$s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
		$s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
		$s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
		$s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
		$s5 = "%sMutex" fullword ascii
		$s6 = "\\ShellIconCache" fullword ascii
		$s7 = "+6Service Pack " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 350KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*) and 1 of ($x*)
}

rule CheshireCat_Gen2 {
	meta:
		description = "Auto-generated rule - from files 32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a, 63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		super_rule = 1
		score = 70
		hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
		hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"
	strings:
		$a1 = "Interface\\%s\\info" fullword ascii
		$a2 = "Interface\\%s\\info\\%s" fullword ascii
		$a3 = "CLSID\\%s\\info\\%s" fullword ascii
		$a4 = "CLSID\\%s\\info" fullword ascii

		$b1 = "Windows Shell Icon Handler" fullword wide
		$b2 = "Microsoft Shell Icon Handler" fullword wide

		$s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
		$s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
		$s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
		$s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
		$s5 = "%sMutex" fullword ascii
		$s6 = "\\ShellIconCache" fullword ascii
		$s7 = "+6Service Pack " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*)
}
