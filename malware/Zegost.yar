/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Zegost : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="10/06/2013"
		description="Zegost Trojan"
		
	strings:
		$signature1={39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}
		$signature2={00 BA DA 22 51 42 6F 6D 65 00}
		
	condition:
		$signature1 and $signature2
}
