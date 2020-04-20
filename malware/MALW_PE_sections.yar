/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule suspicious_packer_section : packer PE {

    meta:

        author = "@j0sm1"
        date = "2016/10/21"
        description = "The packer/protector section names/keywords"
        reference = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
        filetype = "binary"

    strings:

        $s1 = ".aspack" wide ascii
        $s2 = ".adata" wide ascii
        $s3 = "ASPack" wide ascii
        $s4 = ".ASPack" wide ascii
        $s5 = ".ccg" wide ascii
        $s6 = "BitArts" wide ascii
        $s7 = "DAStub" wide ascii
        $s8 = "!EPack" wide ascii
        $s9 = "FSG!" wide ascii
        $s10 = "kkrunchy" wide ascii
        $s11 = ".mackt" wide ascii
        $s12 = ".MaskPE" wide ascii
        $s13 = "MEW" wide ascii
        $s14 = ".MPRESS1" wide ascii
        $s15 = ".MPRESS2" wide ascii
        $s16 = ".neolite" wide ascii
        $s17 = ".neolit" wide ascii
        $s18 = ".nsp1" wide ascii
        $s19 = ".nsp2" wide ascii
        $s20 = ".nsp0" wide ascii
        $s21 = "nsp0" wide ascii
        $s22 = "nsp1" wide ascii
        $s23 = "nsp2" wide ascii
        $s24 = ".packed" wide ascii
        $s25 = "pebundle" wide ascii
        $s26 = "PEBundle" wide ascii
        $s27 = "PEC2TO" wide ascii
        $s28 = "PECompact2" wide ascii
        $s29 = "PEC2" wide ascii
        $s30 = "pec1" wide ascii
        $s31 = "pec2" wide ascii
        $s32 = "PEC2MO" wide ascii
        $s33 = "PELOCKnt" wide ascii
        $s34 = ".perplex" wide ascii
        $s35 = "PESHiELD" wide ascii
        $s36 = ".petite" wide ascii
        $s37 = "ProCrypt" wide ascii
        $s38 = ".RLPack" wide ascii
        $s39 = "RCryptor" wide ascii
        $s40 = ".RPCrypt" wide ascii
        $s41 = ".sforce3" wide ascii
        $s42 = ".spack" wide ascii
        $s43 = ".svkp" wide ascii
        $s44 = "Themida" wide ascii
        $s45 = ".Themida" wide ascii
        $s46 = ".packed" wide ascii
        $s47 = ".Upack" wide ascii
        $s48 = ".ByDwing" wide ascii
        $s49 = "UPX0" wide ascii
        $s50 = "UPX1" wide ascii
        $s51 = "UPX2" wide ascii
        $s52 = ".UPX0" wide ascii
        $s53 = ".UPX1" wide ascii
        $s54 = ".UPX2" wide ascii
        $s55 = ".vmp0" wide ascii
        $s56 = ".vmp1" wide ascii
        $s57 = ".vmp2" wide ascii
        $s58 = "VProtect" wide ascii
        $s59 = "WinLicen" wide ascii
        $s60 = "WWPACK" wide ascii
        $s61 = ".yP" wide ascii
        $s62 = ".y0da" wide ascii
        $s63 = "UPX!" wide ascii

    condition:
        // DOS stub signature                           PE signature
        uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (
            for any of them : ( $ in (0..1024) )
        )
}
