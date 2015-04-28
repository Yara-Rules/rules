/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Dexter_Malware {
	meta:
		description = "Detects the Dexter Trojan/Agent http://goo.gl/oBvy8b"
		author = "Florian Roth"
		reference = "http://goo.gl/oBvy8b"
		date = "2015/02/10"
		score = 70
	strings:
		$s0 = "Java Security Plugin" fullword wide
		$s1 = "%s\\%s\\%s.exe" fullword wide
		$s2 = "Sun Java Security Plugin" fullword wide
		$s3 = "\\Internet Explorer\\iexplore.exe" fullword wide
	condition:
		all of them
}
