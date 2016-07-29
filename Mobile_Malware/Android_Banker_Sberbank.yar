/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
import "androguard"

rule Android_Banker_Sberbank
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android Banker Sberbank"
		source = "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"

	condition:
		androguard.service(/MasterInterceptor/i) and 
		androguard.receiver(/MasterBoot/i) and 
		androguard.filter(/ACTION_POWER_DISCONNECTED/i)
}
