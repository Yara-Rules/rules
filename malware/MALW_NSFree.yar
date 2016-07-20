/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule NSFreeCode : NSFree Family 
{
    meta:
        description = "NSFree code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // push vars then look for MZ
        $ = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $ = { 90 90 90 90 81 3F 50 45 00 00 }
    
    condition:
        all of them
}

rule NSFreeStrings : NSFree Family
{
    meta:
        description = "NSFree Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $ = "\\MicNS\\" nocase
        $ = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       any of them
}

rule NSFree : Family
{
    meta:
        description = "NSFree"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    condition:
        NSFreeCode or NSFreeStrings
}


