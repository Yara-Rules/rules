/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule koodous : official
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		Reference = "https://github.com/dana-at-cp/backdoor-apk"
		
	strings:
		$str_1 = "cnlybnq.qrk" // encrypted string "payload.dex"

	condition:
		$str_1 and 
		androguard.receiver(/\.AppBoot$/)		
}
