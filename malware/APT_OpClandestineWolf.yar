/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule OpClandestineWolf 
{
 
   meta:
        alert_severity = "HIGH"
        log = "false"
        author = "NDF"
        weight = 10
        alert = true
        source = " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html"
        version = 1
        date = "2015-06-23"
        description = "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
        hash0 = "1a4b710621ef2e69b1f7790ae9b7a288"
        hash1 = "917c92e8662faf96fffb8ffe7b7c80fb"
        hash2 = "975b458cb80395fa32c9dda759cb3f7b"
        hash3 = "3ed34de8609cd274e49bbd795f21acc4"
        hash4 = "b1a55ec420dd6d24ff9e762c7b753868"
        hash5 = "afd753a42036000ad476dcd81b56b754"
        hash6 = "fad20abf8aa4eda0802504d806280dd7"
        hash7 = "ab621059de2d1c92c3e7514e4b51751a"
        hash8 = "510b77a4b075f09202209f989582dbea"
        hash9 = "d1b1abfcc2d547e1ea1a4bb82294b9a3"
        hash10 = "4692337bf7584f6bda464b9a76d268c1"
        hash11 = "7cae5757f3ba9fef0a22ca0d56188439"
        hash12 = "1a7ba923c6aa39cc9cb289a17599fce0"
        hash13 = "f86db1905b3f4447eb5728859f9057b5"
        hash14 = "37c6d1d3054e554e13d40ea42458ebed"
        hash15 = "3e7430a09a44c0d1000f76c3adc6f4fa"
        hash16 = "98eb249e4ddc4897b8be6fe838051af7"
        hash17 = "1b57a7fad852b1d686c72e96f7837b44"
        hash18 = "ffb84b8561e49a8db60e0001f630831f"
        hash19 = "98eb249e4ddc4897b8be6fe838051af7"
        hash20 = "dfb4025352a80c2d81b84b37ef00bcd0"
        hash21 = "4457e89f4aec692d8507378694e0a3ba"
        hash22 = "48de562acb62b469480b8e29821f33b8"
        hash23 = "7a7eed9f2d1807f55a9308e21d81cccd"
        hash24 = "6817b29e9832d8fd85dcbe4af176efb6"

   strings:
        $s0 = "flash.Media.Sound()"
        $s1 = "call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)"
        $s2 = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        $s3 = "NetStream"

    condition:
        all of them
}
