/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Backdoor_APT_Mongal
{

    meta:
        author = "@patrickrolsen"
        maltype = "Backdoor.APT.Mongall"
        version = "0.1"
        reference = "fd69a799e21ccb308531ce6056944842" 
        date = "01/04/2014"
    
    strings:
        $author  = "author user"
        $title   = "title Vjkygdjdtyuj" nocase
        $comp    = "company ooo"
        $cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
        $passwd  = "password 00000000"
    
    condition:
        all of them
}

rule MongalCode
{
    meta:
        description = "Mongal code features"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
    
    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        
    condition:
        any of them
}

rule MongalStrings
{
    
    meta:
        description = "Mongal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    strings:
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}

rule Mongal 
{
    
    meta:
        description = "Mongal"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    condition:
        MongalCode or MongalStrings
}


