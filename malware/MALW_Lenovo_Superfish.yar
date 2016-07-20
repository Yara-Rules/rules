/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

/* LENOVO Superfish -------------------------------------------------------- */

rule VisualDiscovery_Lonovo_Superfish_SSL_Hijack {
	meta:
		description = "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"
		author = "Florian Roth / improved by kbandla"
		reference = "https://twitter.com/4nc4p/status/568325493558272000"
		date = "2015/02/19"
		hash1 = "99af9cfc7ab47f847103b5497b746407dc566963"
		hash2 = "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46"
		hash3 = "f12edf2598d8f0732009c5cd1df5d2c559455a0b"
		hash4 = "343af97d47582c8150d63cbced601113b14fcca6"
	strings:
		$mz = { 4d 5a }
		//$s1 = "VisualDiscovery.exe" fullword wide
		$s2 = "Invalid key length used to initialize BlowFish." fullword ascii
		$s3 = "GetPCProxyHandler" fullword ascii
		$s4 = "StartPCProxy" fullword ascii
		$s5 = "SetPCProxyHandler" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 2MB and all of ($s*)
}
