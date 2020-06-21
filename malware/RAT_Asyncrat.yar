/*
   This Yara ruleset is under the GNU-GPLv2 license 
   (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or 
   organization, as long as you use it under this license.
*/

rule win_asyncrat_j1 {

    meta:
        author      = "Johannes Bader @viql"
        date        = "2020-04-26"
        description = "detects AsyncRAT"
        references  = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        tlp         = "white"

    strings:
        $str_anti_1 = "VIRTUAL" wide
        $str_anti_2 = "vmware" wide
        $str_anti_3 = "VirtualBox" wide
        $str_anti_4 = "SbieDll.dll" wide

        $str_miner_1 = "--donate-level=" wide

        $str_b_rev_run    = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $str_b_msg_pack_1 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $str_b_msg_pack_2 = "(never used) type $c1" wide
        $str_b_schtask_1  = "/create /f /sc ONLOGON /RL HIGHEST /tn \"'" wide
        $str_b_schtask_2  = "\"' /tr \"'" wide

        $str_config_1 = "Antivirus" wide
        $str_config_2 = "Pastebin" wide
        $str_config_3 = "HWID" wide
        $str_config_4 = "Installed" wide
        $str_config_5 = "Pong" wide
        $str_config_6 = "Performance" wide

    condition:
        all of ($str_anti_*)  and 
        4 of ($str_config_*) and ( 
            all of ($str_miner_*) or 
            3 of ($str_b_*)
        )
        
}

