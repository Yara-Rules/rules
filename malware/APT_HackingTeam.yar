/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule bin_ndisk {
	meta:
		description = "Hacking Team Disclosure Sample - file ndisk.sys"
		author = "Florian Roth"
		reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
		date = "2015-07-07"
		hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
	strings:
		$s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide 
		$s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide 
		$s3 = "\\Driver\\DeepFrz" fullword wide
		$s4 = "Microsoft Kernel Disk Manager" fullword wide 
		$s5 = "ndisk.sys" fullword wide
		$s6 = "\\Device\\MSH4DEV1" fullword wide
		$s7 = "\\DosDevices\\MSH4DEV1" fullword wide
		$s8 = "built by: WinDDK" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}

rule Hackingteam_Elevator_DLL {
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.dll"
		author = "Florian Roth"
		reference = "http://t.co/EG0qtVcKLh"
		date = "2015-07-07"
		hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"
	strings:
		$s1 = "\\sysnative\\CI.dll" fullword ascii 
		$s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii 
		$s3 = "mitmproxy0" fullword ascii 
		$s4 = "\\insert_cert.exe" fullword ascii
		$s5 = "elevator.dll" fullword ascii
		$s6 = "CRTDLL.DLL" fullword ascii
		$s7 = "fail adding cert" fullword ascii
		$s8 = "DownloadingFile" fullword ascii 
		$s9 = "fail adding cert: %s" fullword ascii
		$s10 = "InternetOpenA fail" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 6 of them
}

rule HackingTeam_Elevator_EXE {
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.exe"
		author = "Florian Roth"
		reference = "Hacking Team Disclosure elevator.c"
		date = "2015-07-07"
		hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
		hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"
		hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"
	strings:
		$x1 = "CRTDLL.DLL" fullword ascii
		$x2 = "\\sysnative\\CI.dll" fullword ascii
		$x3 = "\\SystemRoot\\system32\\CI.dll" fullword ascii
		$x4 = "C:\\\\Windows\\\\Sysnative\\\\ntoskrnl.exe" fullword ascii /* PEStudio Blacklist: strings */

		$s1 = "[*] traversing processes" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "_getkprocess" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "[*] LoaderConfig %p" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "loader.obj" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii /* PEStudio Blacklist: strings */
		$s6 = "[*] token restore" fullword ascii /* PEStudio Blacklist: strings */
		$s7 = "elevator.obj" fullword ascii
		$s8 = "_getexport" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of ($x*) and 3 of ($s*)
}
