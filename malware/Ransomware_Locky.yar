/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-17
	Identifier: Locky
*/

rule Locky_Ransomware {
	meta:
		description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
		author = "Florian Roth (with the help of binar.ly)"
		reference = "https://goo.gl/qScSrE"
		date = "2016-02-17"
		hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"
	strings:
		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863
	condition:
		all of ($o*)
}
