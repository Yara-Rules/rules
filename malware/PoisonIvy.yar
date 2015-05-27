/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule poisonivy : rat
{
	meta:
		description = "Poison Ivy"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://code.google.com/p/volatility/source/browse/trunk/contrib/plugins/malware/poisonivy.py"

	strings:
		$a = { 53 74 75 62 50 61 74 68 ?? 53 4F 46 54 57 41 52 45 5C 43 6C 61 73 73 65 73 5C 68 74 74 70 5C 73 68 65 6C 6C 5C 6F 70 65 6E 5C 63 6F 6D 6D 61 6E 64 [22] 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 41 63 74 69 76 65 20 53 65 74 75 70 5C 49 6E 73 74 61 6C 6C 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C } 
		
	condition:
		$a
}

rule PoisonIvy_Generic_3 {
	meta:
		description = "PoisonIvy RAT Generic Rule"
		author = "Florian Roth"
		date = "2015-05-14"
		hash = "e1cbdf740785f97c93a0a7a01ef2614be792afcd"
	strings:
		$k1 = "Tiger324{" fullword ascii
		
		$s2 = "WININET.dll" fullword ascii
		$s3 = "mscoree.dll" fullword wide
		$s4 = "WS2_32.dll" fullword
		$s5 = "Explorer.exe" fullword wide
		$s6 = "USER32.DLL"
		$s7 = "CONOUT$"
		$s8 = "login.asp"
		
		$h1 = "HTTP/1.0"
		$h2 = "POST"
		$h3 = "login.asp"
		$h4 = "check.asp"
		$h5 = "result.asp"
		$h6 = "upload.asp"
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and
			( 
				$k1 or all of ($s*) or all of ($h*)
			)
}
rule PoisonIvy
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PoisonIvy"
		maltype = "Remote Access Trojan"
		filetype = "exe"

    strings:
    	$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
        $string1 = "CONNECT %s:%i HTTP/1.0"
        $string2 = "ws2_32"
        $string3 = "cks=u"
        $string4 = "thj@h"
        $string5 = "advpack"
    condition:
		$stub at 0x1620 and all of ($string*) or (all of them)
}
