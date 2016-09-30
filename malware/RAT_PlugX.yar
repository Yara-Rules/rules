/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule PlugXStrings : PlugX Family
{
    meta:
        description = "PlugX Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    strings:
        $BootLDR = "boot.ldr" wide ascii
        $Dwork = "d:\\work" nocase
        $Plug25 = "plug2.5"
        $Plug30 = "Plug3.0"
        $Shell6 = "Shell6"
      
    condition:
        $BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}

rule plugX : rat
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "PlugX RAT"
		date = "2014-05-13"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://github.com/mattulm/IR-things/blob/master/volplugs/plugx.py"
		
	strings:
		$v1a = { 47 55 4C 50 00 00 00 00 }
		$v1b = "/update?id=%8.8x" 
		$v1algoa = { BB 33 33 33 33 2B } 
		$v1algob = { BB 44 44 44 44 2B } 
		$v2a = "Proxy-Auth:" 
		$v2b = { 68 A0 02 00 00 } 
		$v2k = { C1 8F 3A 71 } 
		
	condition: 
		$v1a at 0 or $v1b or (($v2a or $v2b) and (($v1algoa and $v1algob) or $v2k))
}

rule PlugX_mw
{ 
	meta:
		maltype = "plugX"
		author = "https://github.com/reed1713"
		reference = "http://www.fireeye.com/blog/technical/targeted-attack/2014/02/operation-greedywonk-multiple-economic-and-foreign-policy-sites-compromised-serving-up-flash-zero-day-exploit.html"
		description = "Malware creates a randomized directory within the appdata roaming directory and launches the malware. Should see multiple events for create process rundll32.exe and iexplorer.exe as it repeatedly uses iexplorer to launch the rundll32 process."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data=/\\AppData\\Roaming\\[0-9]{9,12}\VMwareCplLauncher\.exe/

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="\\Windows\\System32\\rundll32.exe"

		$type2="Microsoft-Windows-Security-Auditing"
		$eventid2="4688"
		$data2="Program Files\\Internet Explorer\\iexplore.exe"
	condition:
		all of them
}

