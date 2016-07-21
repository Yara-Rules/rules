/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Ponmocup : plugins memory
{
 			meta: 
 					description = "Ponmocup plugin detection (memory)"
 					author = "Danny Heppener, Fox-IT"
 					reference = "https://foxitsecurity.files.wordpress.com/2015/12/foxit-whitepaper_ponmocup_1_1.pdf"
 			strings:
					 $1100 = {4D 5A 90 [29] 4C 04}
					 $1201 = {4D 5A 90 [29] B1 04}
					 $1300 = {4D 5A 90 [29] 14 05}
					 $1350 = {4D 5A 90 [29] 46 05}
					 $1400 = {4D 5A 90 [29] 78 05}
					 $1402 = {4D 5A 90 [29] 7A 05}
					 $1403 = {4D 5A 90 [29] 7B 05}
					 $1404 = {4D 5A 90 [29] 7C 05}
					 $1405 = {4D 5A 90 [29] 7D 05}
					 $1406 = {4D 5A 90 [29] 7E 05}
					 $1500 = {4D 5A 90 [29] DC 05}
					 $1501 = {4D 5A 90 [29] DD 05}
					 $1502 = {4D 5A 90 [29] DE 05}
					 $1505 = {4D 5A 90 [29] E1 05}
					 $1506 = {4D 5A 90 [29] E2 05}
					 $1507 = {4D 5A 90 [29] E3 05}
					 $1508 = {4D 5A 90 [29] E4 05}
					 $1509 = {4D 5A 90 [29] E5 05}
					 $1510 = {4D 5A 90 [29] E6 05}
					 $1511 = {4D 5A 90 [29] E7 05}
					 $1512 = {4D 5A 90 [29] E8 05}
					 $1600 = {4D 5A 90 [29] 40 06}
					 $1601 = {4D 5A 90 [29] 41 06}
					 $1700 = {4D 5A 90 [29] A4 06}
					 $1800 = {4D 5A 90 [29] 08 07}
					 $1801 = {4D 5A 90 [29] 09 07}
					 $1802 = {4D 5A 90 [29] 0A 07}
					 $1803 = {4D 5A 90 [29] 0B 07}
					 $2001 = {4D 5A 90 [29] D1 07}
					 $2002 = {4D 5A 90 [29] D2 07}
					 $2003 = {4D 5A 90 [29] D3 07}
					 $2004 = {4D 5A 90 [29] D4 07}
					 $2500 = {4D 5A 90 [29] C4 09}
					 $2501 = {4D 5A 90 [29] C5 09}
					 $2550 = {4D 5A 90 [29] F6 09}
					 $2600 = {4D 5A 90 [29] 28 0A}
					 $2610 = {4D 5A 90 [29] 32 0A}
					 $2700 = {4D 5A 90 [29] 8C 0A}
					 $2701 = {4D 5A 90 [29] 8D 0A}
					 $2750 = {4D 5A 90 [29] BE 0A}
					 $2760 = {4D 5A 90 [29] C8 0A}
					 $2810 = {4D 5A 90 [29] FA 0A}
 			condition:
 					 any of ($1100,$1201,$1300,$1350,$1400,$1402,$1403,$1404,$1405,$1406,
$1500,$1501,$1502,$1505,$1506,$1507,$1508,$1509,$1510,$1511,$1512,$1600,$1601,$1700,$1800,$1801,
$1802,$1803,$2001,$2002,$2003,$2004,$2500,$2501,$2550,$2600,$2610,$2700,$2701,$2750,$2760,$2810)
}
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
