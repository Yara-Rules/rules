/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule PoS_Malware_MalumPOS
{
    meta:
        author = "Trend Micro, Inc."
        date = "2015-05-25"
        description = "Used to detect MalumPOS memory dumper"
        sample_filtype = "exe"
    strings:
        $string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $string2 = "B)[0-9]{13,19}\\"
        $string3 = "[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\"
        $string4 = "TRegExpr(exec): ExecNext Without Exec[Pos]"
        $string5 = /Y:\\PROGRAMS\\.{20,300}\.pas/ 
    condition:
        all of ($string*)
}        

rule PoS_Malware_MalumPOS_Config
{
    meta:
        author = "Florian Roth"
        date = "2015-06-25"
        description = "MalumPOS Config File"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-discovers-malumpos-targets-hotels-and-other-us-industries/"
    strings:
        $s1 = "[PARAMS]"
        $s2 = "Name="
        $s3 = "InterfacesIP="
        $s4 = "Port="
    condition:
        /* all of ($s*) and filename == "log.ini" and filesize < 20KB*/
        all of ($s*) and filesize < 20KB
}

