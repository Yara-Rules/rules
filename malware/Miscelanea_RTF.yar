/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule rtf_multiple
{
meta:
	author = "@patrickrolsen"
	maltype = "Multiple"
	version = "0.1"
	reference = "fd69a799e21ccb308531ce6056944842" 
	date = "01/04/2014"
strings:
	$rtf = { 7b 5c 72 74 ?? ?? } // {\rt01 {\rtf1 {\rtxa
    	$string1  = "author user"
	$string2   = "title Vjkygdjdtyuj" nocase
	$string3    = "company ooo"
	$string4  = "password 00000000"
condition:
    ($rtf at 0) and (all of ($string*))
}
