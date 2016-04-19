/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Description: Rar file with a .js inside
  Author: iHeartMalware
  Priority: 5
  Scope: Against Attachment
  Tags: http://phishme.com/rockloader-new-upatre-like-downloader-pushed-dridex-downloads-malwares/
  Created in PhishMe Triage on April 7, 2016 3:41 PM
*/

rule rar_with_js
{
  strings:
  $h1 = "Rar!" 
  $s1 = ".js" nocase
    
  condition:
    $h1 at 0 and $s1
}



rule RockLoader{
meta:
name = "RockLoader"
description = "RockLoader Malware"
author = "@seanmw"
strings:
$hdr = {4d 5a 90 00}
$op1 = {39 45 f0 0f 8e b0 00 00 00}
$op2 = {32 03 77 73 70 72 69 6e 74 66 41 00 ce 02 53 65}
condition:
$hdr at 0 and all of ($op*) and filesize < 500KB
}
