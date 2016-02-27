/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_pinkLocker : android
{
	meta:
		description = "Yara detection for Android Locker app named Pink Club"
		author = "@5h1vang"
		ref1 = "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/"
		ref2 = "https://analyst.koodous.com/rulesets/1186"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
		
	strings:
		$str_1 = "arnrsiec sisani"
		$str_2 = "rhguecisoijng ts"
		$str_3 = "assets/data.db"
		$str_4 = "res/xml/device_admin_sample.xmlPK" 

	condition:
		androguard.url(/lineout\.pw/) or 
		androguard.certificate.sha1("D88B53449F6CAC93E65CA5E224A5EAD3E990921E") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		all of ($str_*)
		
}
