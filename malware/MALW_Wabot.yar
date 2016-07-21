/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Wabot : Worm
{
	meta:
		author="Kevin Falcoz"
		date="14/08/2015"
		description="Wabot Trojan Worm"

	strings:
		$signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}
		$signature2={73 49 52 43 34}

	condition:
		$signature1 and $signature2
}
