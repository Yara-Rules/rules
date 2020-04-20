/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule batterybotpro : ClickFraud AdFraud SMS Downloader_Trojan android
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
		author = "https://twitter.com/fdrg21"

	condition:

		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)
		
}
