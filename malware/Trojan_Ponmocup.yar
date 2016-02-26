/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
import "pe"
rule Trj_Ponmocup {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                ref ="https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
                description = "Ponmocup Installer"
        strings:
                $mz = { 4d 5a }
                $pac = { 48 8F BB 54 5F 3E 4F 4E }
                $unp = { 8B B8 7C 1F 46 00 33 C8 }
        condition:
                ($mz at 0) and ($pac at 0x61F7C) and ($unp at 0x29F0)
}

rule Trj_Ponmocup_Downloader {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                ref ="https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
                description = "Ponmocup Downloader"
        strings:
                $mz = { 4d 5a }
                $vb5 = "VB5" fullword ascii
                $tpb = "www.thepiratebay.org" fullword wide
                $ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; SV1)" fullword wide
        condition:
                ($mz at 0) and ($vb5) and ($tpb) and ($ua)
}

rule Trj_Ponmocup_dll {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                ref ="https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
                description = "Ponmocup Bot DLL"
        strings:
                $mz = { 4d 5a }
                $pck = { 00 81 23 00 33 3E 00 00 3B F4 56 00 00 00 7D 00 }
                $upk = { 68 F4 14 00 10 A1 6C C0 02 10 FF D0 59 59 E9 7A }
        condition:
                ($mz at 0) and ($pck at 0x8a50) and ($upk at 0x61f)
}
