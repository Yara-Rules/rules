/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-29
   Identifier: GRIZZLY STEPPE
*/

rule GRIZZLY_STEPPE_Malware_1
{

   meta:
      description = "Auto-generated rule - file HRDG022184_certclint.dll"
      author = "Florian Roth"
      reference = "https://goo.gl/WVflzO"
      date = "2016-12-29"
      hash1 = "9f918fb741e951a10e68ce6874b839aef5a26d60486db31e509f8dcaa13acec5"

   strings:
      $s1 = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb" fullword ascii
      $s2 = "Repeat last find command)Replace specific text with different text" fullword wide
      $s3 = "l\\Processor(0)\\% Processor Time" fullword wide
      $s6 = "Self Process" fullword wide
      $s7 = "Default Process" fullword wide
      $s8 = "Star Polk.exe" fullword wide

   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 4 of them )
}

rule GRIZZLY_STEPPE_Malware_2
{

   meta:
      description = "Auto-generated rule - file 9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
      author = "Florian Roth"
      reference = "https://goo.gl/WVflzO"
      date = "2016-12-29"
      hash1 = "9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
      hash2 = "55058d3427ce932d8efcbe54dccf97c9a8d1e85c767814e34f4b2b6a6b305641"
      
   strings:
      $x1 = "GoogleCrashReport.dll" fullword ascii
      $s1 = "CrashErrors" fullword ascii
      $s2 = "CrashSend" fullword ascii
      $s3 = "CrashAddData" fullword ascii
      $s4 = "CrashCleanup" fullword ascii
      $s5 = "CrashInit" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $x1 ) or ( all of them )
}

rule PAS_TOOL_PHP_WEB_KIT_mod 
{
   
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
      author = "US CERT - modified by Florian Roth due to performance reasons"
      date = "2016/12/29"
   
   strings:
      $php = "<?php"
      $base64decode1 = "='base'.("
      $strreplace = "str_replace(\"\\n\", ''"
      $md5 = ".substr(md5(strrev("
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   
   condition:
      $php at 0 and (filesize > 10KB and filesize < 30KB) and #cookie == 2 and #isset == 3 and all of them
}

rule WebShell_PHP_Web_Kit_v3
{

   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      author = "Florian Roth"
      date = "2016/01/01"

   strings:
      $php = "<?php $"
      $php2 = "@assert(base64_decode($_REQUEST["
      $s1 = "(str_replace(\"\\n\", '', '"
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii

   condition:
      ( $php at 0 or $php2 ) and filesize > 8KB and filesize < 100KB and all of ($s*)
}

rule WebShell_PHP_Web_Kit_v4
{

   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      author = "Florian Roth"
      date = "2016/01/01"

   strings:
      $php = "<?php $"
      $s1 = "(StR_ReplAcE(\"\\n\",'',"
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii

   condition:
      $php at 0 and filesize > 8KB and filesize < 100KB and 2 of ($s*)
}

