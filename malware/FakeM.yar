/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule HTMLVariant : FakeM Family HTML Variant
{
	meta:
		description = "Identifier for html variant of FAKEM"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		// decryption loop
		$s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
		//mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
		$s2 = { C6 45 F? (3?|4?) }

	condition:
		$s1 and #s2 == 16

}

rule FakeM_Generic {
	meta:
		description = "Detects FakeM malware samples"
		author = "Florian Roth"
		reference = "http://researchcenter.paloaltonetworks.com/2016/01/scarlet-mimic-years-long-espionage-targets-minority-activists/"
		date = "2016-01-25"
		score = 85
		hash1 = "631fc66e57acd52284aba2608e6f31ba19e2807367e33d8704f572f6af6bd9c3"
		hash2 = "3d9bd26f5bd5401efa17690357f40054a3d7b438ce8c91367dbf469f0d9bd520"
		hash3 = "53af257a42a8f182e97dcbb8d22227c27d654bea756d7f34a80cc7982b70aa60"
		hash4 = "4a4dfffae6fc8be77ac9b2c67da547f0d57ffae59e0687a356f5105fdddc88a3"
		hash5 = "7bfbf49aa71b8235a16792ef721b7e4195df11cb75371f651595b37690d108c8"
		hash6 = "12dedcdda853da9846014186e6b4a5d6a82ba0cf61d7fa4cbe444a010f682b5d"
		hash7 = "9adda3d95535c6cf83a1ba08fe83f718f5c722e06d0caff8eab4a564185971c5"
		hash8 = "3209ab95ca7ee7d8c0140f95bdb61a37d69810a7a23d90d63ecc69cc8c51db90"
		hash9 = "41948c73b776b673f954f497e09cc469d55f27e7b6e19acb41b77f7e64c50a33"
		hash10 = "53cecc0d0f6924eacd23c49d0d95a6381834360fbbe2356778feb8dd396d723e"
		hash11 = "523ad50b498bfb5ab688d9b1958c8058f905b634befc65e96f9f947e40893e5b"
	strings:
		$a1 = "\\system32\\kernel32.dll" fullword ascii
		$a2 = "\\boot.lnk" fullword ascii
		$a3 = "%USERPROFILE%" fullword ascii /* Goodware String - occured 16 times */

		$b1 = "Wizard.EXE" fullword wide
		$b2 = "CommandLineA" fullword ascii

		$c1 = "\\system32\\kernel32.dll" fullword ascii
		$c2 = "\\aapz.tmp" fullword ascii

		$e1 = "C:\\Documents and Settings\\A\\" fullword ascii
		$e2 = "\\svchost.exe" fullword ascii
		$e3 = "\\Perform\\Release\\Perform.pdb" fullword ascii

		$f1 = "Browser.EXE" fullword wide
		$f2 = "\\browser.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and
		( all of ($a*) or all of ($b*) or all of ($c*) or all of ($e*) or 1 of ($f*) )
}
