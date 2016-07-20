/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/

rule Powerkatz_DLL_Generic {
	meta:
		description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
		author = "Florian Roth"
		reference = "PowerKatz Analysis"
		date = "2016-02-05"
		super_rule = 1
		score = 80
		hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
		hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
		hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
	strings:
		$s1 = "%3u - Directory '%s' (*.kirbi)" fullword wide
		$s2 = "%*s  pPublicKey         : " fullword wide
		$s3 = "ad_hoc_network_formed" fullword wide
		$s4 = "<3 eo.oe ~ ANSSI E>" fullword wide
		$s5 = "\\*.kirbi" fullword wide

		$c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
		$c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}
