/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-06
	Identifier: Threat Group 3390
*/

rule HttpBrowser_RAT_dropper_Gen1 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "808de72f1eae29e3c1b2c32be1b84c5064865a235866edf5e790d2a7ba709907"
		hash2 = "f6f966d605c5e79de462a65df437ddfca0ad4eb5faba94fc875aba51a4b894a7"
		hash3 = "f424965a35477d822bbadb821125995616dc980d3d4f94a68c87d0cd9b291df9"
		hash4 = "01441546fbd20487cb2525a0e34e635eff2abe5c3afc131c7182113220f02753"
		hash5 = "8cd8159f6e4689f572e2087394452e80e62297af02ca55fe221fe5d7570ad47b"
		hash6 = "10de38419c9a02b80ab7bf2f1f1f15f57dbb0fbc9df14b9171dc93879c5a0c53"
		hash7 = "c2fa67e970d00279cec341f71577953d49e10fe497dae4f298c2e9abdd3a48cc"
	strings:
		$x1 = "1001=cmd.exe" fullword ascii 
		$x2 = "1003=ShellExecuteA" fullword ascii 
		$x3 = "1002=/c del /q %s" fullword ascii
		$x4 = "1004=SetThreadPriority" fullword ascii

		/* $s1 = "pnipcn.dllUT" fullword ascii
		$s2 = "ssonsvr.exeUT" fullword ascii
		$s3 = "navlu.dllUT" fullword ascii
		$s4 = "@CONOUT$" fullword wide 
		$s5 = "VPDN_LU.exeUT" fullword ascii
		$s6 = "msi.dll.urlUT" fullword ascii
		$s7 = "setup.exeUT" fullword ascii 
		$s8 = "pnipcn.dll.urlUT" fullword ascii
		$s9 = "ldvpreg.exeUT" fullword ascii */

		$op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b } /* Opcode */
		$op1 = { e8 85 34 00 00 59 59 8b 86 b4 } /* Opcode */
		$op2 = { 8b 45 0c 83 38 00 0f 84 97 } /* Opcode */
		$op3 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
		$op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d } /* Opcode */
		$op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of ($x*) and 1 of ($op*)
}

rule HttpBrowser_RAT_Sample1 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
		hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
	strings:
		$s0 = "update.hancominc.com" fullword wide 
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $s0
}

rule HttpBrowser_RAT_Sample2 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
	strings:
		$s0 = "nKERNEL32.DLL" fullword wide
		$s1 = "WUSER32.DLL" fullword wide
		$s2 = "mscoree.dll" fullword wide
		$s3 = "VPDN_LU.exeUT" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule HttpBrowser_RAT_Gen {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 90
		hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
		hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
		hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
		hash4 = "07133f291fe022cd14346cd1f0a649aa2704ec9ccadfab809ca9c48b91a7d81b"
		hash5 = "0f8893e87ddec3d98e39a57f7cd530c28e36d596ea0a1d9d1e993dc2cae0a64d"
		hash6 = "108e6633744da6efe773eb78bd0ac804920add81c3dde4b26e953056ac1b26c5"
		hash7 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
		hash8 = "1277ede988438d4168bb5b135135dd3b9ae7d9badcdf1421132ca4692dd18386"
		hash9 = "19be90c152f7a174835fd05a0b6f722e29c648969579ed7587ae036679e66a7b"
		hash10 = "1e7133bf5a9fe5e462321aafc2b7770b8e4183a66c7fef14364a0c3f698a29af"
		hash11 = "2264e5e8fcbdcb29027798b200939ecd8d1d3ad1ef0aef2b8ce7687103a3c113"
		hash12 = "2a1bdeb0a021fb0bdbb328bd4b65167d1f954c871fc33359cb5ea472bad6e13e"
		hash13 = "259a2e0508832d0cf3f4f5d9e9e1adde17102d2804541a9587a9a4b6f6f86669"
		hash14 = "240d9ce148091e72d8f501dbfbc7963997d5c2e881b4da59a62975ddcbb77ca2"
		hash15 = "211a1b195cf2cc70a2caf8f1aafb8426eb0e4bae955e85266490b12b5322aa16"
		hash16 = "2d25c6868c16085c77c58829d538b8f3dbec67485f79a059f24e0dce1e804438"
		hash17 = "2d932d764dd9b91166361d8c023d64a4480b5b587a6087b0ce3d2ac92ead8a7d"
		hash18 = "3556722d9aa37beadfa6ba248a66576f767e04b09b239d3fb0479fa93e0ba3fd"
		hash19 = "365e1d4180e93d7b87ba28ce4369312cbae191151ac23ff4a35f45440cb9be48"
		hash20 = "36c49f18ce3c205152eef82887eb3070e9b111d35a42b534b2fb2ee535b543c0"
		hash21 = "3eeb1fd1f0d8ab33f34183893c7346ddbbf3c19b94ba3602d377fa2e84aaad81"
		hash22 = "3fa8d13b337671323e7fe8b882763ec29b6786c528fa37da773d95a057a69d9a"
	strings:
		$s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide 
		$s1 = "HttpBrowser/1.0" fullword wide
		$s2 = "set cmd : %s" ascii fullword
		$s3 = "\\config.ini" wide fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}

rule PlugX_NvSmartMax_Gen {
	meta:
		description = "Threat Group 3390 APT Sample - PlugX NvSmartMax Generic"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "718fc72942b9b706488575c0296017971170463f6f40fa19b08fc84b79bf0cef"
		hash2 = "1c0379481d17fc80b3330f148f1b87ff613cfd2a6601d97920a0bcd808c718d0"
		hash3 = "555952aa5bcca4fa5ad5a7269fece99b1a04816d104ecd8aefabaa1435f65fa5"
		hash4 = "71f7a9da99b5e3c9520bc2cc73e520598d469be6539b3c243fb435fe02e44338"
		hash5 = "65bbf0bd8c6e1ccdb60cf646d7084e1452cb111d97d21d6e8117b1944f3dc71e"
	strings:
		$s0 = "NvSmartMax.dll" fullword ascii
		$s1 = "NvSmartMax.dll.url" fullword ascii
		$s2 = "Nv.exe" fullword ascii
		$s4 = "CryptProtectMemory failed" fullword ascii 
		$s5 = "CryptUnprotectMemory failed" fullword ascii 
		$s7 = "r%.*s(%d)%s" fullword wide
		$s8 = " %s CRC " fullword wide

		$op0 = { c6 05 26 49 42 00 01 eb 4a 8d 85 00 f8 ff ff 50 } /* Opcode */
		$op1 = { 8d 85 c8 fe ff ff 50 8d 45 c8 50 c6 45 47 00 e8 } /* Opcode */
		$op2 = { e8 e6 65 00 00 50 68 10 43 41 00 e8 56 84 00 00 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of ($s*) and 1 of ($op*)
}

rule HttpBrowser_RAT_dropper_Gen2 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
		hash2 = "dfa984174268a9f364d856fd47cfaca75804640f849624d69d81fcaca2b57166"
	strings:
		$s1 = "navlu.dll.urlUT" fullword ascii
		$s2 = "VPDN_LU.exeUT" fullword ascii
		$s3 = "pnipcn.dllUT" fullword ascii
		$s4 = "\\ssonsvr.exe" fullword ascii
		$s5 = "/c del /q %s" fullword ascii
		$s6 = "\\setup.exe" fullword ascii 
		$s7 = "msi.dllUT" fullword ascii

		$op0 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
		$op1 = { e8 dd 07 00 00 ff 35 d8 fb 40 00 8b 35 7c a0 40 } /* Opcode */
		$op2 = { 83 fb 08 75 2c 8b 0d f8 af 40 00 89 4d dc 8b 0d } /* Opcode */
		$op3 = { c7 43 18 8c 69 40 00 e9 da 01 00 00 83 7d f0 00 } /* Opcode */
		$op4 = { 6a 01 e9 7c f8 ff ff bf 1a 40 00 96 1b 40 00 01 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 3 of ($s*) and 1 of ($op*)
}

rule ThreatGroup3390_Strings {
	meta:
		description = "Threat Group 3390 APT - Strings"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60
	strings:
		$s1 = "\"cmd\" /c cd /d \"c:\\Windows\\Temp\\\"&copy" ascii
		$s2 = "svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014"
		$s3 = "ren *.rar *.zip" fullword ascii
		$s4 = "c:\\temp\\ipcan.exe" fullword ascii
		$s5 = "<%eval(Request.Item(\"admin-na-google123!@#" ascii
	condition:
		1 of them and filesize < 30KB
}

rule ThreatGroup3390_C2 {
	meta:
		description = "Threat Group 3390 APT - C2 Server"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60
	strings:
		$s1 = "api.apigmail.com"
		$s2 = "apigmail.com"
		$s3 = "backup.darkhero.org"
		$s4 = "bel.updatawindows.com"
		$s5 = "binary.update-onlines.org"
		$s6 = "blackcmd.com"
		$s7 = "castle.blackcmd.com"
		$s8 = "ctcb.blackcmd.com"
		$s9 = "darkhero.org"
		$s10 = "dav.local-test.com"
		$s11 = "test.local-test.com"
		$s12 = "dev.local-test.com"
		$s13 = "ocean.local-test.com"
		$s14 = "ga.blackcmd.com"
		$s15 = "helpdesk.blackcmd.com"
		$s16 = "helpdesk.csc-na.com"
		$s17 = "helpdesk.hotmail-onlines.com"
		$s18 = "helpdesk.lnip.org"
		$s19 = "hotmail-onlines.com"
		$s20 = "jobs.hotmail-onlines.com"
		$s21 = "justufogame.com"
		$s22 = "lnip.org"
		$s23 = "local-test.com"
		$s24 = "login.hansoftupdate.com"
		$s25 = "long.update-onlines.org"
		$s26 = "longlong.update-onlines.org"
		$s27 = "longshadow.dyndns.org"
		$s28 = "longshadow.update-onlines.org"
		$s29 = "longykcai.update-onlines.org"
		$s30 = "lostself.update-onlines.org"
		$s31 = "mac.navydocument.com"
		$s32 = "mail.csc-na.com"
		$s33 = "mantech.updatawindows.com"
		$s34 = "micr0soft.org"
		$s35 = "microsoft-outlook.org"
		$s36 = "mtc.navydocument.com"
		$s37 = "navydocument.com"
		$s38 = "mtc.update-onlines.org"
		$s39 = "news.hotmail-onlines.com"
		$s40 = "oac.3322.org"
		$s41 = "ocean.apigmail.com"
		$s42 = "pchomeserver.com"
		$s43 = "registre.organiccrap.com"
		$s44 = "security.pomsys.org"
		$s45 = "services.darkhero.org"
		$s46 = "sgl.updatawindows.com"
		$s47 = "shadow.update-onlines.org"
		$s48 = "sonoco.blackcmd.com"
		$s49 = "test.logmastre.com"
		$s50 = "up.gtalklite.com"
		$s51 = "updatawindows.com"
		$s52 = "update-onlines.org"
		$s53 = "update.deepsoftupdate.com"
		$s54 = "update.hancominc.com"
		$s55 = "update.micr0soft.org"
		$s56 = "update.pchomeserver.com"
		$s57 = "urs.blackcmd.com"
		$s58 = "wang.darkhero.org"
		$s59 = "webs.local-test.com"
		$s60 = "word.apigmail.com"
		$s61 = "wordpress.blackcmd.com"
		$s62 = "working.blackcmd.com"
		$s63 = "working.darkhero.org"
		$s64 = "working.hotmail-onlines.com"
		$s65 = "www.trendmicro-update.org"
		$s66 = "www.update-onlines.org"
		$s67 = "x.apigmail.com"
		$s68 = "ykcai.update-onlines.org"
		$s69 = "ykcailostself.dyndns-free.com"
		$s70 = "ykcainobody.dyndns.org"
		$s71 = "zj.blackcmd.com"
		$s72 = "laxness-lab.com"
		$s73 = "google-ana1ytics.com"
		$s74 = "www.google-ana1ytics.com"
		$s75 = "ftp.google-ana1ytics.com"
		$s76 = "hotmailcontact.net"
		$s77 = "208.115.242.36"
		$s78 = "208.115.242.37"
		$s79 = "208.115.242.38"
		$s80 = "66.63.178.142"
		$s81 = "72.11.148.220"
		$s82 = "72.11.141.133"
		$s83 = "74.63.195.236"
		$s84 = "74.63.195.236"
		$s85 = "74.63.195.237"
		$s86 = "74.63.195.238"
		$s87 = "103.24.0.142"
		$s88 = "103.24.1.54"
		$s89 = "106.187.45.162"
		$s90 = "192.151.236.138"
		$s91 = "192.161.61.19"
		$s92 = "192.161.61.20"
		$s93 = "192.161.61.22"
		$s94 = "103.24.1.54"
		$s95 = "67.215.232.179"
		$s96 = "96.44.177.195"
		$s97 = "49.143.192.221"
		$s98 = "67.215.232.181"
		$s99 = "67.215.232.182"
		$s100 = "96.44.182.243"
		$s101 = "96.44.182.245"
		$s102 = "96.44.182.246"
		$s103 = "49.143.205.30"
		$s104 = "working_success@163.com"
		$s105 = "ykcaihyl@163.com"
		$s106 = "working_success@163.com"
		$s107 = "yuming@yinsibaohu.aliyun.com"
	condition:
		uint16(0) == 0x5a4d and 1 of them
}
