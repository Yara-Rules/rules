/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT3102Code
{

    meta:
        description = "3102 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }

    condition:
        any of them
}

rule APT3102Strings
{
    
    meta:
        description = "3102 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    strings:
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"

    condition:
       any of them
}
