/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-02-19
	Identifier: BlackEnergy Malware
*/

rule BlackEnergy_BE_2 {
   meta:
      description = "Detects BlackEnergy 2 Malware"
      author = "Florian Roth"
      reference = "http://goo.gl/DThzLz"
      date = "2015/02/19"
      hash = "983cfcf3aaaeff1ad82eb70f77088ad6ccedee77"
   strings:
      $s0 = "<description> Windows system utility service  </description>" fullword ascii
      $s1 = "WindowsSysUtility - Unicode" fullword wide
      $s2 = "msiexec.exe" fullword wide
      $s3 = "WinHelpW" fullword ascii
      $s4 = "ReadProcessMemory" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and all of ($s*)
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-03
	Identifier: BlackEnergy Malware
*/

rule BlackEnergy_VBS_Agent {
	meta:
		description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs"
		author = "Florian Roth"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		hash = "b90f268b5e7f70af1687d9825c09df15908ad3a6978b328dc88f96143a64af0f"
	strings:
		$s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
		$s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
		$s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
	condition:
		filesize < 1KB and 2 of them
}

rule DropBear_SSH_Server {
	meta:
		description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
		author = "Florian Roth"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		score = 50
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
	strings:
		$s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
		$s2 = "Badly formatted command= authorized_keys option" fullword ascii
		$s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
		$s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
		$s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule BlackEnergy_BackdoorPass_DropBear_SSH {
	meta:
		description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
		author = "Florian Roth"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
	strings:
		$s1 = "passDs5Bu9Te7" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $s1
}

/* Super Rules ------------------------------------------------------------- */

rule BlackEnergy_KillDisk_1 {
	meta:
		description = "Detects KillDisk malware from BlackEnergy"
		author = "Florian Roth"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		score = 80
		super_rule = 1
		hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
		hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
		hash3 = "c7536ab90621311b526aefd56003ef8e1166168f038307ae960346ce8f75203d"
		hash4 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"
	strings:
		$s0 = "system32\\cmd.exe" fullword ascii
		$s1 = "system32\\icacls.exe" fullword wide
		$s2 = "/c del /F /S /Q %c:\\*.*" fullword ascii
		$s3 = "shutdown /r /t %d" fullword ascii
		$s4 = "/C /Q /grant " fullword wide
		$s5 = "%08X.tmp" fullword ascii
		$s6 = "/c format %c: /Y /X /FS:NTFS" fullword ascii
		$s7 = "/c format %c: /Y /Q" fullword ascii
		$s8 = "taskhost.exe" fullword wide /* Goodware String - occured 1 times */
		$s9 = "shutdown.exe" fullword wide /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 8 of them
}

rule BlackEnergy_KillDisk_2 {
	meta:
		description = "Detects KillDisk malware from BlackEnergy"
		author = "Florian Roth"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		score = 80
		super_rule = 1
		hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
		hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
		hash3 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"
	strings:
		$s0 = "%c:\\~tmp%08X.tmp" fullword ascii
		$s1 = "%s%08X.tmp" fullword ascii
		$s2 = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" fullword wide
		$s3 = "%ls_%ls_%ls_%d.~tmp" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 3 of them
}

rule BlackEnergy_Driver_USBMDM {
	meta:
		description = "Auto-generated rule - from files 7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094, b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a, edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
		author = "Florian Roth"
		reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
		date = "2016-01-04"
		super_rule = 1
		hash1 = "7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094"
		hash2 = "b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a"
		hash3 = "edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
		hash4 = "ac13b819379855af80ea3499e7fb645f1c96a4a6709792613917df4276c583fc"
		hash5 = "7a393b3eadfc8938cbecf84ca630e56e37d8b3d23e084a12ea5a7955642db291"
		hash6 = "405013e66b6f137f915738e5623228f36c74e362873310c5f2634ca2fda6fbc5"
		hash7 = "244dd8018177ea5a92c70a7be94334fa457c1aab8a1c1ea51580d7da500c3ad5"
		hash8 = "edcd1722fdc2c924382903b7e4580f9b77603110e497393c9947d45d311234bf"
	strings:
		$s1 = "USB MDM Driver" fullword wide
		$s2 = "KdDebuggerNotPresent" fullword ascii /* Goodware String - occured 50 times */
		$s3 = "KdDebuggerEnabled" fullword ascii /* Goodware String - occured 69 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule BlackEnergy_Driver_AMDIDE {
	meta:
		description = "Auto-generated rule - from files 32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614, 3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2, 90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c, 97be6b2cec90f655ef11ed9feef5b9ef057fd8db7dd11712ddb3702ed7c7bda1"
		author = "Florian Roth"
		reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
		date = "2016-01-04"
		super_rule = 1
		hash1 = "32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614"
		hash2 = "3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2"
		hash3 = "90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c"
		hash4 = "97be6b2cec90f655ef11ed9feef5b9ef057fd8db7dd11712ddb3702ed7c7bda1"
		hash5 = "5111de45210751c8e40441f16760bf59856ba798ba99e3c9532a104752bf7bcc"
		hash6 = "cbc4b0aaa30b967a6e29df452c5d7c2a16577cede54d6d705ca1f095bd6d4988"
		hash7 = "1ce0dfe1a6663756a32c69f7494ad082d293d32fe656d7908fb445283ab5fa68"
	strings:
		$s1 = " AMD IDE driver" fullword wide
		$s2 = "SessionEnv" fullword wide
		$s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
		$s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}
