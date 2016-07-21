/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule ScarhiknStrings : Scarhikn Family
{
    meta:
        description = "Scarhikn Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "9887___skej3sd"
        $ = "haha123"
        
    condition:
       any of them
}



rule ScarhiknCode : Scarhikn Family 
{
    meta:
        description = "Scarhikn code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
        $ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }
    
    condition:
        any of them
}

rule Scarhikn : Family
{
    meta:
        description = "Scarhikn"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        ScarhiknCode or ScarhiknStrings
}







