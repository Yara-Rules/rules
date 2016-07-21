/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule universal_1337_stealer_serveur : Stealer
{
	meta:
		author="Kevin Falcoz"
		date="24/02/2013"
		description="Universal 1337 Stealer Serveur"
		
	strings:
		$signature1={2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A} /*[S-P-L-I-T]*/
		$signature2={2A 5B 48 2D 45 2D 52 2D 45 5D 2A} /*[H-E-R-E]*/
		$signature3={46 54 50 7E} /*FTP~*/
		$signature4={7E 31 7E 31 7E 30 7E 30} /*~1~1~0~0*/
		
	condition:
		$signature1 and $signature2 or $signature3 and $signature4
}
