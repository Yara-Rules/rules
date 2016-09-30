/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Kovter
{ 
	meta:
		maltype = "Kovter"
    reference = "http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE"
		date = "9-19-2016"
		description = "fileless malware"
	strings:
		$type="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid="4688" wide ascii
		$data="Windows\\System32\\regsvr32.exe" wide ascii
		
		$type1="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid1="4689" wide ascii
		$data1="Windows\\System32\\mshta.exe" wide ascii
		
		$type2="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid2="4689" wide ascii
		$data2="Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide ascii

		$type3="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid3="4689" wide ascii
		$data3="Windows\\System32\\wbem\\WmiPrvSE.exe" wide ascii


	condition:
		all of them
}
