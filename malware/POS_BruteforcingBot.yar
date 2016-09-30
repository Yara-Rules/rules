/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule POS_bruteforcing_bot
{ 
	meta:
		maltype = "botnet"
    ref = "https://github.com/reed1713"
		reference = "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop"
		date = "3/11/2014"
		description = "botnet bruteforcing POS terms via RDP"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="\\AppData\\Roaming\\lsacs.exe"

	condition:
		all of them
}
