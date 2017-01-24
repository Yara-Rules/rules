/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule COZY_FANCY_BEAR_Hunt 
{

    meta:
        description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
        author = "Florian Roth"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
        date = "2016-06-14"

    strings:
        $s1 = "185.100.84.134" ascii wide fullword
        $s2 = "58.49.58.58" ascii wide fullword
        $s3 = "218.1.98.203" ascii wide fullword
        $s4 = "187.33.33.8" ascii wide fullword
        $s5 = "185.86.148.227" ascii wide fullword
        $s6 = "45.32.129.185" ascii wide fullword
        $s7 = "23.227.196.217" ascii wide fullword

    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_pagemgr_Hunt 
{

    meta:
        description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
        author = "Florian Roth"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
        date = "2016-06-14"

    strings:
        $s1 = "pagemgr.exe" wide fullword

    condition:
        uint16(0) == 0x5a4d and 1 of them
}
