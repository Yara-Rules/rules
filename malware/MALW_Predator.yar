/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Predator_The_Thief : Predator_The_Thief {
   meta:
        description = "Yara rule for Predator The Thief v2.3.5 & +"
        author = "Fumik0_"
        date = "2018/10/12"
        source = "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"
   strings:
        $mz = { 4D 5A }

        $hex1 = { BF 00 00 40 06 } 
        $hex2 = { C6 04 31 6B }
        $hex3 = { C6 04 31 63 }
        $hex4 = { C6 04 31 75 }
        $hex5 = { C6 04 31 66 }

        $s1 = "sqlite_" ascii wide
   condition:
        $mz at 0 and all of ($hex*) and all of ($s*)
}
