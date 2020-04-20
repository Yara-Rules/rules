/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule andr_sk_bank
{
	meta:
		description = "Yara rule for Banking trojan targeting South Korean banks"
		sample = "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad"
		source = "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "NPKI"
		$str_2 = "portraitCallBack("
		$str_3 = "android.app.extra.DEVICE_ADMIN"
		$str_4 = "SMSReceiver&imsi="
		$str_5 = "com.ahnlab.v3mobileplus"

	condition:
		androguard.package_name("com.qbjkyd.rhsxa") or
		androguard.certificate.sha1("543382EDDAFC05B435F13BBE97037BB335C2948B") or
		(androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
		all of ($str_*))
}
