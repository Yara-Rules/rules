/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Njrat: RAT
{
    meta:
        description = "Njrat"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(F)romBase64String/
        $string2 = /(B)ase64String/
        $string3 = /(C)onnected/ wide ascii
        $string4 = /(R)eceive/
        $string5 = /(S)end/ wide ascii
        $string6 = /(D)ownloadData/ wide ascii
        $string7 = /(D)eleteSubKey/ wide ascii
        $string8 = /(g)et_MachineName/
        $string9 = /(g)et_UserName/
        $string10 = /(g)et_LastWriteTime/
        $string11 = /(G)etVolumeInformation/
        $string12 = /(O)SFullName/ wide ascii
        $string13 = /(n)etsh firewall/ wide
        $string14 = /(c)md\.exe \/k ping 0 & del/ wide
        $string15 = /(c)md\.exe \/c ping 127\.0\.0\.1 & del/ wide
        $string16 = /(c)md\.exe \/c ping 0 -n 2 & del/ wide
        $string17 = {7C 00 27 00 7C 00 27 00 7C}

    condition:
        10 of them
}
rule njrat1: RAT
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-27"
        description = "Identify njRat"
    strings:
        $a1 = "netsh firewall add allowedprogram " wide
        $a2 = "SEE_MASK_NOZONECHECKS" wide

        $b1 = "[TAP]" wide
        $b2 = " & exit" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}
