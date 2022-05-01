/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "androguard"

rule Android_RuMMS
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/04/02"
		description = "This rule try to detects Android.Banking.RuMMS"
		sample = "13569bc8343e2355048a4bccbe92a362dde3f534c89acff306c800003d1d10c6 "
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

	condition:
		androguard.package_name("org.starsizew") or
		androguard.package_name("com.tvone.untoenynh") or
		androguard.package_name("org.zxformat") and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
		
}

rule Android_RuMMS_0
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detects Android.Banking.RuMMS"
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

	condition:
		(androguard.service(/\.Tb/) and 
		 androguard.service(/\.Ad/) and 
		 androguard.receiver(/\.Ac/) and 
		 androguard.receiver(/\.Ma/)) or
        (androguard.url(/http\:\/\/37\.1\.207/) and 
		 androguard.url(/\/api\/\?id\=7/))
		
}
