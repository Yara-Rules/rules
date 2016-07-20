/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT_WIN_Gh0st_ver : RAT
{
meta:
   author = "@BryanNolen"
   date = "2012-12"
   type = "APT"
   version = "1.1"
   ref = "Detection of Gh0st RAT server DLL component"
   ref1 = "http://www.mcafee.com/au/resources/white-papers/foundstone/wp-know-your-digital-enemy.pdf"
 strings:  
   $library = "deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly"
   $capability = "GetClipboardData"
   $capability1 = "capCreateCaptureWindowA"
   $capability2 = "CreateRemoteThread"
   $capability3 = "WriteProcessMemory"
   $capability4 = "LsaRetrievePrivateData"
   $capability5 = "AdjustTokenPrivileges"
   $function = "ResetSSDT"
   $window = "WinSta0\\Default"
   $magic = {47 6C 6F 62 61 6C 5C [5-9] 20 25 64}    /* $magic = "Gh0st" */
 condition:
   all of them
}

rule Gh0st : RAT
{
    meta:
        description = "Gh0st"
	author = "botherder https://github.com/botherder"

    strings:
        $ = /(G)host/
        $ = /(i)nflate 1\.1\.4 Copyright 1995-2002 Mark Adler/
        $ = /(d)eflate 1\.1\.4 Copyright 1995-2002 Jean-loup Gailly/
        $ = /(%)s\\shell\\open\\command/
        $ = /(G)etClipboardData/
        $ = /(W)riteProcessMemory/
        $ = /(A)djustTokenPrivileges/
        $ = /(W)inSta0\\Default/
        $ = /(#)32770/
        $ = /(#)32771/
        $ = /(#)32772/
        $ = /(#)32774/

    condition:
        all of them
}

rule gh0st

{

meta:
	author = "https://github.com/jackcr/"

   strings:
      $a = { 47 68 30 73 74 ?? ?? ?? ?? ?? ?? ?? ?? 78 9C }
      $b = "Gh0st Update"

   condition:
      any of them

}
