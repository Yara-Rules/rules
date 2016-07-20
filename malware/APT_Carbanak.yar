/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-09-03
	Identifier: Carbanak Rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule Carbanak_0915_1 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
	strings:
		$s1 = "evict1.pdb" fullword ascii
		$s2 = "http://testing.corp 0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule Carbanak_0915_2 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
	strings:
		$x1 = "8Rkzy.exe" fullword wide

		$s1 = "Export Template" fullword wide
		$s2 = "Session folder with name '%s' already exists." fullword ascii
		$s3 = "Show Unconnected Endpoints (Ctrl+U)" fullword ascii
		$s4 = "Close All Documents" fullword wide
		$s5 = "Add &Resource" fullword ascii
		$s6 = "PROCEXPLORER" fullword wide /* Goodware String - occured 1 times */
		$s7 = "AssocQueryKeyA" fullword ascii /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and ( $x1 or all of ($s*) )
}

rule Carbanak_0915_3 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
	strings:
		$s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
		$s2 = "SHInvokePrinterCommandA" fullword ascii
		$s3 = "Ycwxnkaj" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}
