/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-02
	Identifier: Emissary Malware
*/

rule Emissary_APT_Malware_1 {
	meta:
		description = "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"
		author = "Florian Roth"
		reference = "http://goo.gl/V0epcf"
		date = "2016-01-02"
		score = 75
		hash1 = "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab"
		hash2 = "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629"
		hash3 = "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290"
		hash4 = "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664"
		hash5 = "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc"
		hash6 = "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b"
		hash7 = "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8"
		hash8 = "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9"
		hash9 = "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d"
		hash10 = "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538"
		hash11 = "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051"
		hash12 = "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0"
		hash13 = "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb"
	strings:
		$s1 = "cmd.exe /c %s > %s" fullword ascii
		$s2 = "execute cmd timeout." fullword ascii
		$s3 = "rundll32.exe \"%s\",Setting" fullword ascii
		$s4 = "DownloadFile - exception:%s." fullword ascii
		$s5 = "CDllApp::InitInstance() - Evnet create successful." fullword ascii
		$s6 = "UploadFile - EncryptBuffer Error" fullword ascii
		$s7 = "WinDLL.dll" fullword wide
		$s8 = "DownloadFile - exception:%s,code:0x%08x." fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" fullword ascii
		$s10 = "CDllApp::InitInstance() - Evnet already exists." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 3 of them
}
