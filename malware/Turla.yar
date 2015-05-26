/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule WaterBug_turla_dll 
{
    meta:
        description = "Symantec Waterbug Attack - Trojan Turla DLL"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://www.symantec.com/connect/blogs/turla-spying-tool-targets-governments-and-diplomats"   

    strings:
        $a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
   
    condition:
        pe.exports("ee") and $a
}
