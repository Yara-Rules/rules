/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Nanocore_RAT_Gen_1 {
	meta:
		description = "Detetcs the Nanocore RAT and similar malware"
		author = "Florian Roth"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		score = 70
		hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"
	strings:
		$x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
		$x2 = "RunPE1" fullword ascii
		$x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
		$x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
		$x5 = "Monitorinjection" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}

rule Nanocore_RAT_Gen_2 {
	meta:
		description = "Detetcs the Nanocore RAT"
		author = "Florian Roth"
		score = 100
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"
	strings:
		$x1 = "NanoCore.ClientPluginHost" fullword ascii
		$x2 = "IClientNetworkHost" fullword ascii
		$x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or ( all of them )
}

rule Nanocore_RAT_Sample_1 {
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		author = "Florian Roth"
		score = 75
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"
	strings:
		$x1 = "TbSiaEdJTf9m1uTnpjS.n9n9M7dZ7FH9JsBARgK" fullword wide
		$x2 = "1EF0D55861681D4D208EC3070B720C21D885CB35" fullword ascii
		$x3 = "popthatkitty.Resources.resources" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule Nanocore_RAT_Sample_2 {
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		author = "Florian Roth"
		score = 75
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
	strings:
		$s1 = "U4tSOtmpM" fullword ascii
		$s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" fullword wide
		$s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*)
}
