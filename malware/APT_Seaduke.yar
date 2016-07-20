/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule SeaDuke_Sample {
	meta:
		description = "SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d"
		author = "Florian Roth"
		reference = "http://goo.gl/MJ0c2M"
		date = "2015-07-14"
		score = 70
		hash = "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e"
	strings:
		$s0 = "bpython27.dll" fullword ascii
		$s1 = "email.header(" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "LogonUI.exe" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "Crypto.Cipher.AES(" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "mod is NULL - %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}
