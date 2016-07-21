/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule VidgrabCode : Vidgrab Family 
{
    meta:
        description = "Vidgrab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        
    condition:
        all of them
}

rule VidgrabStrings : Vidgrab Family
{
    meta:
        description = "Vidgrab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "IDI_ICON5" wide ascii
        $ = "starter.exe"
        $ = "wmifw.exe"
        $ = "Software\\rar"
        $ = "tmp092.tmp"
        $ = "temp1.exe"
        
    condition:
       3 of them
}

rule Vidgrab : Family
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        VidgrabCode or VidgrabStrings
}
