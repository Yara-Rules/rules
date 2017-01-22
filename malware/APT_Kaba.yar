/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule rtf_Kaba_jDoe
{

meta:
    author = "@patrickrolsen"
    maltype = "APT.Kaba"
    filetype = "RTF"
    version = "0.1"
    description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
    date = "2013-12-10"

strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }

condition:
    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
}

