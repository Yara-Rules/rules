/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Grozlex : Stealer
{
	meta:
		author="Kevin Falcoz"
		date="20/08/2013"
		description="Grozlex Stealer - Possible HCStealer"
		
	strings:
		$signature={4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}
	
	condition:
		$signature
}
