/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Furtim_nativeDLL {
	meta:
		description = "Detects Furtim malware - file native.dll"
		author = "Florian Roth"
		reference = "MISP 3971"
		date = "2016-06-13"
		hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"
	strings:
		$s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii

		$op0 = { e0 b3 42 00 c7 84 24 ac } /* Opcode */
		$op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 } /* Opcode */
		$op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 900KB and $s1 or all of ($op*)
}

rule Furtim_Parent_1 {
	meta:
		description = "Detects Furtim Parent Malware"
		author = "Florian Roth"
		reference = "https://sentinelone.com/blogs/sfg-furtims-parent/"
		date = "2016-07-16"
		hash1 = "766e49811c0bb7cce217e72e73a6aa866c15de0ba11d7dda3bd7e9ec33ed6963"
	strings:
		/* RC4 encryption password */
		$x1 = "dqrChZonUF" fullword ascii
		/* Other strings */
		$s1 = "Egistec" fullword wide
		$s2 = "Copyright (C) 2016" fullword wide
		/* Op Code */
		$op1 = { c0 ea 02 88 55 f8 8a d1 80 e2 03 }
		$op2 = { 5d fe 88 55 f9 8a d0 80 e2 0f c0 }
		$op3 = { c4 0c 8a d9 c0 eb 02 80 e1 03 88 5d f8 8a d8 c0 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 900KB and
		( $x1 or ( all of ($s*) and all of ($op*) ) ) ) or
		all of them
}
