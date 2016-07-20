/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule TerminatorRat : RAT 
{
	meta:
		description = "Terminator RAT" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-10-24"
		filetype = "memory"
		version = "1.0" 
		ref1 = "http://www.fireeye.com/blog/technical/malware-research/2013/10/evasive-tactics-terminator-rat.html" 

	strings:
		$a = "Accelorator"
		$b = "<html><title>12356</title><body>"

	condition:
		all of them
}



rule TROJAN_Notepad_shell_crew : Trojan {
        meta:
                author = "RSA_IR"
                Date     = "4Jun13"
                File     = "notepad.exe v 1.1"
                MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
        strings:
                $s1 = "75BAA77C842BE168B0F66C42C7885997"
                $s2 = "B523F63566F407F3834BCC54AAA32524"
        condition:
                $s1 or $s2
}
