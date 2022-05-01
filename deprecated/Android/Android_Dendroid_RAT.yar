/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Dendroid : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid RAT"
	strings:
    	$s1 = "/upload-pictures.php?"
    	$s2 = "Opened Dialog:"
    	$s3 = "com/connect/MyService"
    	$s4 = "android/os/Binder"
    	$s5 = "android/app/Service"
   	condition:
    	all of them

}

rule Dendroid_2 : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via Droidian service"
	strings:
    	$a = "Droidian"
    	$b = "DroidianService"
   	condition:
    	all of them

}

rule Dendroid_3 : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via ServiceReceiver"
	strings:
    	$1 = "ServiceReceiver"
    	$2 = "Dendroid"
   	condition:
    	all of them

}

import "androguard"
rule Android_Dendroid
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detect Dendroid"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"

	condition:
		androguard.service(/com.connect/i) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i)
}
