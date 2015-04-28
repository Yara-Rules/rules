/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Android_Malware : iBanking
{
	meta:
		author = "Xylitol xylitol@malwareint.com"
		date = "2014-02-14"
		description = "Match first two bytes, files and string present in iBanking"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3166"
		
	strings:
		// Generic android
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		// iBanking related
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}
