/* Yara rule to detect Mirai Okiru generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/

private rule is__Mirai_gen7 {
	meta:
		description = "Generic detection for MiraiX version 7"
		reference = "http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-05"

	strings:
        	$st01 = "/bin/busybox rm" fullword nocase wide ascii
        	$st02 = "/bin/busybox echo" fullword nocase wide ascii
        	$st03 = "/bin/busybox wget" fullword nocase wide ascii
        	$st04 = "/bin/busybox tftp" fullword nocase wide ascii
        	$st05 = "/bin/busybox cp" fullword nocase wide ascii
        	$st06 = "/bin/busybox chmod" fullword nocase wide ascii
		$st07 = "/bin/busybox cat" fullword nocase wide ascii

	condition:
        	5 of them
}

private rule is__elf {

	meta:
		author = "@mmorenog,@yararules"
		
	strings:
		$header = { 7F 45 4C 46 }

	condition:
		$header at 0
}

rule Mirai_Okiru {
	meta:
		description = "Detects Mirai Okiru MALW"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"

	strings:
		$hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
		$hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
		// noted some Okiru variant doesnt have below function, uncomment to seek specific x86 bins
    // $st07 = "iptables -F\n" fullword nocase wide ascii
    
	condition:
    		all of them
		and is__elf
		and is__Mirai_gen7
		and filesize < 100KB 
}
