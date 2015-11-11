/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule sakula_v1_0
{
    meta:
        description = "Sakula v1.0"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "=%s&type=%d"
        $m4 = "?photoid="
        $m5 = "iexplorer"
                $m6 = "net start \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $MZ = "MZ"
    condition:
        $MZ at 0 and all of ($m*) and not $v1_1
}

rule sakula_v1_1
{
    meta:
        description = "Sakula v1.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "=%s&type=%d"
        $m4 = "?photoid="
        $m5 = "iexplorer"
                $m6 = "net start \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v1_2
{
    meta:
        description = "Sakula v1.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $v1_2 = "CCPUpdate"

        $MZ = "MZ"
    condition:
        $MZ at 0 and $m1 and $m2 and $m3 and $v1_2 and not $v1_1
}

rule sakula_v1_3
{
    meta:
        description = "Sakula v1.3"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""

        $v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v1_4
{
    meta:
        description = "Sakula v1.4"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""

        $v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}
