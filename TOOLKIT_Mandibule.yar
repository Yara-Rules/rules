/* 		Yara rule to detect ELF Linux process injector toolkit "mandibule" generic.
   		name: TOOLKIT_Mandibule.yar analyzed by unixfreaxjp. 
   		This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   		and  open to any user or organization, as long as you use it under this license.
*/

private rule is__str_mandibule_gen1 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$str01 = "shared arguments too big" fullword nocase wide ascii
		$str02 = "self inject pid: %" fullword nocase wide ascii
		$str03 = "injected shellcode at 0x%lx" fullword nocase wide ascii        	
		$str04 = "target pid: %d" fullword nocase wide ascii        	
		$str05 = "mapping '%s' into memory at 0x%lx" fullword nocase wide ascii
		$str06 = "shellcode injection addr: 0x%lx" fullword nocase wide ascii
		$str07 = "loading elf at: 0x%llx" fullword nocase wide ascii
	condition:
                4 of them
}

private rule is__hex_top_mandibule {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$hex01 = { 48 8D 05 43 01 00 00 48 89 E7 FF D0 } // st
		$hex02 = { 53 48 83 EC 50 48 89 7C 24 08 48 8B 44 24 08 } // mn
		$hex03 = { 48 81 EC 18 02 00 00 89 7C 24 1C 48 89 74 } // pt
		$hex04 = { 53 48 81 EC 70 01 01 00 48 89 7C 24 08 48 8D 44 24 20 48 05 00 00 } // ld
	condition:
                3 of them 
}

private rule is__elf {
	meta:
		author = "@mmorenog,@yararules"
	strings:
		$header = { 7F 45 4C 46 }
	condition:
		$header at 0
}

rule TOOLKIT_Mandibule {
	meta:
		description = "Generic detection for ELF Linux process injector mandibule generic"
		reference = "https://imgur.com/a/MuHSZtC"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-05-31"
	condition:
		((is__str_mandibule_gen1) and  (is__hex_top_mandibule))
		and is__elf
		and filesize < 30KB 
}

