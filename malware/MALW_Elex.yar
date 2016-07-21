/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
import "pe"
rule Trj_Elex_Installer_NSIS {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                description = "Elex Installer NSIS"
                ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        strings:
                $mz = { 4d 5a }
                $str1 = {4e 75 6c 6c 73 6f 66 74 }
                $str2 = {b7 a2 d5 dc 0c d6 a6 3a}
        condition:
                ($mz at 0) and ($str1 at 0xA008) and ($str2 at 0x1c8700)
}
rule Trj_Elex_Installer {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                description = "Elex Installer"
                ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        strings:
                $mz = { 4d 5a }
                $str1 = {65 00 76 00 65 00 72 00 79 00 74 00 68 00 69 00 6e 00 67 00}
                $str2 = "IsWow64Process"
                $str3 = "SSFK"
        condition:
                ($mz at 0) and ($str1) and ($str2) and ($str3)
}
rule Trj_Elex_Service32 {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                description = "Elex Service 32 bits"
                ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        strings:
                $mz = { 4d 5a }
                $str1 = "http://xa.xingcloud.com/v4/sof-everything/"
                $str2 = "http://www.mysearch123.com"
                $str3 = "21e223b3f0c97db3c281da1g7zccaefozzjcktmlma"
        condition:
                (pe.machine == pe.MACHINE_I386) and ($mz at 0) and ($str1) and ($str2) and ($str3)
}
rule Trj_Elex_Service64 {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                description = "Elex Service 64 bits"
                ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        strings:
                $mz = { 4d 5a }
                $str1 = "http://xa.xingcloud.com/v4/sof-everything/"
                $str2 = "http://www.mysearch123.com"
                $str3 = "21e223b3f0c97db3c281da1g7zccaefozzjcktmlma"
        condition:
               (pe.machine == pe.MACHINE_AMD64) and ($mz at 0) and ($str1) and ($str2) and ($str3)
}
rule Trj_Elex_Dll32 {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                description = "Elex DLL 32 bits"
                ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        strings:
                $mz = { 4d 5a }
                $str1 = {59 00 72 00 72 00 65 00 68 00 73 00}
             $str2 = "RookIE/1.0"
        condition:
                (pe.machine == pe.MACHINE_I386) and (pe.characteristics & pe.DLL) and ($mz at 0) and ($str1) and ($str2)
}
rule Trj_Elex_Dll64 {
        meta:
                author = "Centro Criptológico Nacional (CCN)"
                description = "Elex DLL 64 bits"
                ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        strings:
                $mz = { 4d 5a }
                $str1 = {59 00 72 00 72 00 65 00 68 00 73 00}
             $str2 = "RookIE/1.0"
        condition:
                (pe.machine == pe.MACHINE_AMD64) and (pe.characteristics & pe.DLL) and ($mz at 0) and ($str1) and ($str2)
}
