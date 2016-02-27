/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
    and open to any user or organization, as long as you use it under this license.
*/

rule dropperMapin : android
{
    meta:
        author = "https://twitter.com/plutec_net"
        source = "https://koodous.com/"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        description = "This rule detects mapin dropper files"
        sample = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
        sample2 = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"

    strings:
        $a = ":Write APK file (from txt in assets) to SDCard sucessfully!"
        $b = "4Write APK (from Txt in assets) file to SDCard  Fail!"
        $c = "device_admin"

    condition:
        all of them
}


rule Mapin : android
{
    meta:
        author = "https://twitter.com/plutec_net"
        source = "https://koodous.com/"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        description = "Mapin trojan, not for droppers"
        sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

    strings:
        $a = "138675150963" //GCM id
        $b = "res/xml/device_admin.xml"
        $c = "Device registered: regId ="
        

    condition:
        all of them
        
}
