/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule iexpl0reCode : iexpl0ree Family 
{
    meta:
        description = "iexpl0re code features"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
        $ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
        $ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
        $ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
        // 88h decrypt
        $ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        
    condition:
        any of them
}

rule iexpl0reStrings : iexpl0re Family
{
    meta:
        description = "Strings used by iexpl0re"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = "%USERPROFILE%\\IEXPL0RE.EXE"
        $ = "\"<770j (("
        $ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
        $ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
        $ = "LoaderV5.dll"
        // stage 2
        $ = "POST /index%0.9d.asp HTTP/1.1"
        $ = "GET /search?n=%0.9d&"
        $ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
        $ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
        $ = "BASTARD_&&_BITCHES_%0.8x"
        $ = "c:\\bbb\\eee.txt"
        
    condition:
        any of them

}

rule iexpl0re : Family
{
    meta:
        description = "iexpl0re family"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
   
    condition:
        iexpl0reCode or iexpl0reStrings
        
}


