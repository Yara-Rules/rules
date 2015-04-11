/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule BLOWFISH_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for Blowfish constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }	
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
                6 of them
}

rule MD5_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for MD5 constants"
                date = "2014-01"
                version = "0.2"
        strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }	
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
                5 of them
}

rule RC6_Constants {
        meta:
                author = "chort (@chort0)"
                description = "Look for RC6 magic constants in binary"
                reference = "https://twitter.com/mikko/status/417620511397400576"
                reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
                date = "2013-12"
                version = "0.2"
        strings:
                $c1 = { B7E15163 }
                $c2 = { 9E3779B9 }
                $c3 = { 6351E1B7 }
                $c4 = { B979379E }
        condition:
                2 of them
}

rule RIPEMD160_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for RIPEMD-160 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}
rule SHA1_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA1 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
                5 of them
}

rule SHA512_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA384/SHA512 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}

rule WHIRLPOOL_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for WhirlPool constants"
                date = "2014-02"
                version = "0.1"
        strings:
		$c0 = { 18186018c07830d8 }
		$c1 = { d83078c018601818 }
		$c2 = { 23238c2305af4626 }
		$c3 = { 2646af05238c2323 }
	condition:
                2 of them
}


