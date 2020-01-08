/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule smsfraud1 : android
{
    meta:
        author = "Antonio Sánchez https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        description = "This rule detects a kind of SMSFraud trojan"
        sample = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
        sample2 = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"

    strings:
        $a = "E!QQAZXS"
        $b = "__exidx_end"
        $c = "res/layout/notify_apkinstall.xmlPK"

    condition:
    all of them
        
}

rule smsfraud2 : android {
    meta:
        author = "Antonio Sánchez https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        sample = "0200a454f0de2574db0b58421ea83f0f340bc6e0b0a051fe943fdfc55fea305b"
        sample2 = "bff3881a8096398b2ded8717b6ce1b86a823e307c919916ab792a13f2f5333b6"

    strings:
        $a = "pluginSMS_decrypt"
        $b = "pluginSMS_encrypt"
        $c = "__dso_handle"
        $d = "lib/armeabi/libmylib.soUT"
        $e = "]Diok\"3|"
    condition:
        all of them
}
