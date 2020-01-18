/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"


rule Android_Switcher
{
	meta:
		description = "This rule detects Android wifi Switcher variants"
		sample = "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
		source = "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
    source2 = "https://koodous.com/rulesets/2049"
    author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "javascript:scrollTo"		
		$str_5 = "javascript:document.getElementById('dns1')"
		$str_6 = "admin:"

		$dns_2 = "101.200.147.153"
		$dns_3 = "112.33.13.11"
		$dns_4 = "120.76.249.59"


	condition:
		androguard.certificate.sha1("2421686AE7D976D19AB72DA1BDE273C537D2D4F9") or 
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and 
		($dns_2 or $dns_3 or $dns_4) and all of ($str_*))
}
