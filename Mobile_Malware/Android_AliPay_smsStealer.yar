/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_AliPay_smsStealer : android
{
	meta:
		description = "Yara rule for detection of Fake AliPay Sms Stealer"
		sample = "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b"
		source = "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html"
		ref = "https://analyst.koodous.com/rulesets/1192"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "START_SERVICE"
		$str_2 = "extra_key_sms"
		$str_3 = "android.provider.Telephony.SMS_RECEIVED"
		$str_4 = "mPhoneNumber"

	condition:
		androguard.certificate.sha1("0CDFC700D0BDDC3EA50D71B54594BF3711D0F5B2") or
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 		
		all of ($str_*)
}
