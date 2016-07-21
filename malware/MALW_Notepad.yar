/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule TROJAN_Notepad {
    meta:
        Author = "RSA_IR"
        Date     = "4Jun13"
        File     = "notepad.exe v 1.1"
        MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
    strings:
        $s1 = "75BAA77C842BE168B0F66C42C7885997"
        $s2 = "B523F63566F407F3834BCC54AAA32524"
    condition:
        $s1 or $s2
}


