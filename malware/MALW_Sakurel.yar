/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Sakurel_backdoor
{
	meta:
		maltype = "Sakurel backdoor"
    ref = "https://github.com/reed1713"
		reference = "http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2"
		description = "malware creates a process in the temp directory and performs the sysprep UAC bypass method."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe" nocase
	condition:
		all of them
}
