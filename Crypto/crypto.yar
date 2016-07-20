/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule BLOWFISH_Constants: crypto {
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

rule MD5_Constants : crypto {
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

rule RC6_Constants : crypto {
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

rule RIPEMD160_Constants : crypto {
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
rule SHA1_Constants : crypto {
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

rule SHA512_Constants : crypto {
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

rule WHIRLPOOL_Constants : crypto {
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

rule DarkEYEv3_Cryptor : crypto {
	meta:
		description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
		author = "Florian Roth"
		reference = "http://darkeyev3.blogspot.fi/"
		date = "2015-05-24"
		hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
		hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
		hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
		hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
		hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
		hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
		hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
		hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
		hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"
		score = 55
	strings:
		$s0 = "\\DarkEYEV3-" 
	condition:
		uint16(0) == 0x5a4d and $s0
}
