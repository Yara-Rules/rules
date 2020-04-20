/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

/*
    Androguard module used in this rule file is under development by people at https://koodous.com/.
    You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/


import "androguard"

rule spynote_variants
{
    meta:
        author = "5h1vang https://analyst.koodous.com/analysts/5h1vang"
        description = "Yara rule for detection of different Spynote Variants"
        source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
        rule_source = "https://analyst.koodous.com/rulesets/1710"

    strings:
        $str_1 = "SERVER_IP" nocase
        $str_2 = "SERVER_NAME" nocase
        $str_3 = "content://sms/inbox"
        $str_4 = "screamHacker" 
        $str_5 = "screamon"
    condition:
        androguard.package_name("dell.scream.application") or 
        androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") or
        all of ($str_*)
}
