/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule CVE_2015_1701_Taihou {
	meta:
		description = "CVE-2015-1701 compiled exploit code"
		author = "Florian Roth"
		reference = "http://goo.gl/W4nU0q"
		date = "2015-05-13"
		hash1 = "90d17ebd75ce7ff4f15b2df951572653efe2ea17"
		hash2 = "acf181d6c2c43356e92d4ee7592700fa01e30ffb"
		hash3 = "b8aabe12502f7d55ae332905acee80a10e3bc399"
		hash4 = "d9989a46d590ebc792f14aa6fec30560dfe931b1"
		hash5 = "63d1d33e7418daf200dc4660fc9a59492ddd50d9"
		score = 70
	strings:	
		$s3 = "VirtualProtect" fullword
		$s4 = "RegisterClass"
		$s5 = "LoadIcon"
		$s6 = "PsLookupProcessByProcessId" fullword ascii 
		$s7 = "LoadLibraryExA" fullword ascii
		$s8 = "gSharedInfo" fullword

		$w1 = "user32.dll" wide
		$w2 = "ntdll" wide	
	condition:
		uint16(0) == 0x5a4d and filesize < 160KB and all of ($s*) and 1 of ($w*)
}
