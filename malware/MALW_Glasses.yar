/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule GlassesCode : Glasses Family 
{
    meta:
        description = "Glasses code features"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        
    condition:
        any of them
}

rule GlassesStrings : Glasses Family
{
    meta:
        description = "Strings used by Glasses"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = "thequickbrownfxjmpsvalzydg"
        $ = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
        $ = "\" target=\"NewRef\"></a>"
 
    condition:
        all of them

}

rule Glasses : Family
{
    meta:
        description = "Glasses family"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
   
    condition:
        GlassesCode or GlassesStrings
        
}
