/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule cxpidStrings : cxpid Family
{
    meta:
        description = "cxpid Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}

rule cxpidCode : cxpid Family 
{
    meta:
        description = "cxpid code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        $entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }
    
    condition:
        any of them
}

rule cxpid : Family
{
    meta:
        description = "cxpid"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        cxpidCode or cxpidStrings
}
