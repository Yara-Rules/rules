/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_Godlike
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule will be able to tag all the samples with local exploits."
		source = "http://blog.trendmicro.com/trendlabs-security-intelligence/godless-mobile-malware-uses-multiple-exploits-root-devices/"

	strings:
		$a = "libgodlikelib.so"
	condition:
		(androguard.service(/godlike\.s/i) and
		androguard.service(/godlike\.g/i) and
        androguard.receiver(/godlike\.e/i)) or
		$a
		}

rule Android_Godlike_2
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule will be able to tag all the samples with remote exploits."
		source = "http://blog.trendmicro.com/trendlabs-security-intelligence/godless-mobile-malware-uses-multiple-exploits-root-devices/"

	strings:
		$a_1 = "libroot.so"
		$a_2 = "silent91_arm_bin.root"
		$a_3 = "libr.so"
		$a_4 = "libpl_droidsonroids_gif.so"
	condition:
		(androguard.service(/FastInstallService/i) and
		androguard.service(/DownloadService/i)) and 
		any of ($a_*)
}
