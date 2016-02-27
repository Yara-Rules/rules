/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


rule SlemBunk : android
{
	meta:
		description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
		author = "@plutec_net"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		source = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"

	strings:
		$a = "#intercept_sms_start"
		$b = "#intercept_sms_stop"
		$c = "#block_numbers"
		$d = "#wipe_data"
		$e = "Visa Electron"

	condition:
		all of them
		
}
