/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-13
	Identifier: Sofacy Fysbis
*/

rule Sofacy_Fybis_ELF_Backdoor_Gen1 : Sofacy Linux Backdoor APT APT28 {
	meta:
		description = "Detects Sofacy Fysbis Linux Backdoor_Naikon_APT_Sample1"
		author = "Florian Roth"
		reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
		date = "2016-02-13"
		score = 80
		hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
		hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
	strings:
		$x1 = "Your command not writed to pipe" fullword ascii
		$x2 = "Terminal don`t started for executing command" fullword ascii
		$x3 = "Command will have end with \\n" fullword ascii

		$s1 = "WantedBy=multi-user.target' >> /usr/lib/systemd/system/" fullword ascii
		$s2 = "Success execute command or long for waiting executing your command" fullword ascii
		$s3 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" fullword ascii
		$s4 = "rm -f /usr/lib/systemd/system/" fullword ascii
		$s5 = "ExecStart=" fullword ascii
		$s6 = "<table><caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 500KB and 1 of ($x*) ) or
		( 1 of ($x*) and 3 of ($s*) )
}

rule Sofacy_Fysbis_ELF_Backdoor_Gen2  : Sofacy Linux Backdoor APT APT28 {
	meta:
		description = "Detects Sofacy Fysbis Linux Backdoor"
		author = "Florian Roth"
		reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
		date = "2016-02-13"
		score = 80
		hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
		hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
		hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"
	strings:
		$s1 = "RemoteShell" ascii
		$s2 = "basic_string::_M_replace_dispatch" fullword ascii
		$s3 = "HttpChannel" ascii
	condition:
		uint16(0) == 0x457f and filesize < 500KB and all of them
}
