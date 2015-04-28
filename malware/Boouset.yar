/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule BoousetCode : Boouset Family 
{
    meta:
        description = "Boouset code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
        
    condition:
        any of them
}

