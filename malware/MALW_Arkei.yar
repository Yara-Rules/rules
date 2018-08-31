/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Arkei : Arkei 
{
    meta:
        Author = "Fumik0_" 
        Description = "Arkei Stealer"
        Date = "2018/07/10"
        Hash = "5632c89fe4c7c2c87b69d787bbf0a5b4cc535f1aa02699792888c60e0ef88fc5"

    strings:
        $s1 = "Arkei" wide ascii
        $s2 = "/server/gate" wide ascii
        $s3 = "/server/grubConfig" wide ascii
        $s4 = "\\files\\" wide ascii
        $s5 = "SQLite" wide ascii

    condition:
        all of ($s*)	
}
