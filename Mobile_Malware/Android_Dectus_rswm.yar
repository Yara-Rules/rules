/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_Dogspectus_rswm
{
	meta:
		author = "https://twitter.com/5h1vang"
		description = "Yara rule for Dogspectus intial ransomware apk"
		sample = "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	strings:
		$str_1 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_2 = "Tap ACTIVATE to continue with software update"
		
		
	condition:
		(androguard.package_name("net.prospectus") and
		 androguard.app_name("System update")) or
		 
		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or
		
		(androguard.activity(/Loganberry/i) or 
		androguard.activity("net.prospectus.pu") or 
		androguard.activity("PanickedActivity")) or 
		
		(androguard.permission(/android.permission.INTERNET/) and
		 androguard.permission(/android.permission.WAKE_LOCK/) and 
		 androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		 all of ($str_*))
		 	
		
}
