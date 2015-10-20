/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-18
	Identifier: Fareit Oct 2015
*/

rule Fareit_Trojan_Oct15 {
	meta:
		description = "Detects Fareit Trojan from Sep/Oct 2015 Wave"
		author = "Florian Roth"
		reference = "http://goo.gl/5VYtlU"
		date = "2015-10-18"
		score = 80
		super_rule = 1
		hash1 = "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3"
		hash2 = "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997"
		hash3 = "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d"
		hash4 = "76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae"
		hash5 = "9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f"
		hash6 = "c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9"
		hash7 = "ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa"
	strings:
		$s1 = "ebai.exe" fullword wide
		$s2 = "Origina" fullword wide
	condition:
		uint16(0) == 0x5a4d and $s1 in (0..30000) and $s2 in (0..30000)
}
