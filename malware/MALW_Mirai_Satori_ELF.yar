/* Yara rule to detect Mirai Satori generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/

private rule is__Mirai_Satori_gen {
	meta:
		description = "Detects Mirai Satori_gen"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"

	strings:
		$st08 = "tftp -r satori" fullword nocase wide ascii
		$st09 = "/bins/satori" fullword nocase wide ascii
		$st10 = "satori" fullword nocase wide ascii
		$st11 = "SATORI" fullword nocase wide ascii

	condition:
		2 of them
}

rule Mirai_Satori {
	meta:
		description = "Detects Mirai Satori MALW"
		date = "2018-01-09"

	strings:
		$hexsts01 = { 63 71 75 ?? 62 6B 77 62 75 }
		$hexsts02 = { 53 54 68 72 75 64 62 }
		$hexsts03 = { 28 63 62 71 28 70 66 73 64 6F 63 68 60 } 

	condition:
		all of them
		and is__elf
		and is__Mirai_gen7
		and is__Mirai_Satori_gen
		and filesize < 100KB 
}
