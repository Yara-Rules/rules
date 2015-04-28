/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule CrowdStrike_Shamoon_DroppedFile { 
	meta:
		description = "Rule to detect Shamoon malware http://goo.gl/QTxohN"
		reference = "http://www.rsaconference.com/writable/presentations/file_upload/exp-w01-hacking-exposed-day-of-destruction.pdf"
	strings:
		$testn123 = "test123" wide
		$testn456 = "test456" wide
		$testn789 = "test789" wide
		$testdomain = "testdomain.com" wide $pingcmd = "ping -n 30 127.0.0.1 >nul" wide
	condition:
		(any of ($testn*) or $pingcmd) and $testdomain
}
