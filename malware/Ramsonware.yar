/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule CryptoLocker_set1
{
meta:
	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-13"
	description = "Detection of Cryptolocker Samples"
	
strings:
	$string0 = "static"
	$string1 = " kscdS"
	$string2 = "Romantic"
	$string3 = "CompanyName" wide
	$string4 = "ProductVersion" wide
	$string5 = "9%9R9f9q9"
	$string6 = "IDR_VERSION1" wide
	$string7 = "  </trustInfo>"
	$string8 = "LookFor" wide
	$string9 = ":n;t;y;"
	$string10 = "        <requestedExecutionLevel level"
	$string11 = "VS_VERSION_INFO" wide
	$string12 = "2.0.1.0" wide
	$string13 = "<assembly xmlns"
	$string14 = "  <trustInfo xmlns"
	$string15 = "srtWd@@"
	$string16 = "515]5z5"
	$string17 = "C:\\lZbvnoVe.exe" wide
condition:
	8 of ($string*)
}

rule CryptoLocker_rule2
{
meta:
	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-14"
	description = "Detection of CryptoLocker Variants"
strings:
	$string0 = "2.0.1.7" wide
	$string1 = "    <security>"
	$string2 = "Romantic"
	$string3 = "ProductVersion" wide
	$string4 = "9%9R9f9q9"
	$string5 = "IDR_VERSION1" wide
	$string6 = "button"
	$string7 = "    </security>"
	$string8 = "VFileInfo" wide
	$string9 = "LookFor" wide
	$string10 = "      </requestedPrivileges>"
	$string11 = " uiAccess"
	$string12 = "  <trustInfo xmlns"
	$string13 = "last.inf"
	$string14 = " manifestVersion"
	$string15 = "FFFF04E3" wide
	$string16 = "3,31363H3P3m3u3z3"
condition:
	8 of ($string*)
}

rule SVG_LoadURL {
	meta:
		description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
		author = "Florian Roth"
		reference = "http://goo.gl/psjCCc"
		date = "2015-05-24"
		hash1 = "ac8ef9df208f624be9c7e7804de55318"
		hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
		hash3 = "7e2be5cc785ef7711282cea8980b9fee"
		hash4 = "4e2c6f6b3907ec882596024e55c2b58b"
		score = 50
	strings:
		$s1 = "</svg>" nocase
		$s2 = "<script>" nocase
		$s3 = "location.href='http" nocase
	condition:
		all of ($s*) and filesize < 600
}
rule BackdoorFCKG: CTB_Locker_Ransomware
{
meta:
author = "ISG"
date = "2015-01-20"
reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
description = "CTB_Locker"

strings:
$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
$string2 = "keme132.DLL" 
$string3 = "klospad.pdb" 
condition:
3 of them 
}
