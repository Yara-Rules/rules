/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule android_overlayer
{
	meta:
		description = "This rule detects the banker trojan with overlaying functionality"
		source =  "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "tel:"
		$str_2 = "lockNow" nocase
		$str_3 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_4 = "Cmd_conf" nocase
		$str_5 = "Sms_conf" nocase
		$str_6 = "filter2" 

	condition:
		androguard.certificate.sha1("6994ED892E7F0019BCA74B5847C6D5113391D127") or 
		
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and 
		all of ($str_*))
}
