/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule YahLover : Worm
{
	meta:
		author="Kevin Falcoz"
		date="10/06/2013"
		description="YahLover"
		
	strings:
		$signature1={42 00 49 00 54 00 52 00 4F 00 54 00 41 00 54 00 45 00 00 00 42 00 49 00 54 00 53 00 48 00 49 00 46 00 54 00 00 00 00 00 42 00 49 00 54 00 58 00 4F 00 52}
		
	condition:
		$signature1
}

