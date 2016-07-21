/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-13
	Identifier: Upatre Campaign October 2015
*/

rule Upatre_Hazgurut {
	meta:
		description = "Detects Upatre malware - file hazgurut.exe"
		author = "Florian Roth"
		reference = "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7"
		date = "2015-10-13"
		score = 70
		hash1 = "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50"
		hash2 = "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92"
		hash3 = "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3"
		hash4 = "c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a"
		hash5 = "a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70"
		hash6 = "f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9"
		hash7 = "b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2"
		hash8 = "6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3"
		hash9 = "33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041"
		hash10 = "2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273"
		hash11 = "3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3"
		hash12 = "951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274"
		hash13 = "bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295"
		hash14 = "8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d"
	strings:
		$a1 = "barcod" fullword ascii

		$s0 = "msports.dll" fullword ascii
		$s1 = "nddeapi.dll" fullword ascii
		$s2 = "glmf32.dll" fullword ascii
		$s3 = "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\">" fullword ascii
		$s4 = "cmutil.dll" fullword ascii
		$s5 = "mprapi.dll" fullword ascii
		$s6 = "glmf32.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB
		and $a1 in (0..4000)
		and all of ($s*)
}
