// This rule has been modified by @mmorenog @yararules to fix some syntax errors, it's not the original rule

import "pe"

rule WhiskeyBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "74eac0461c40316689ac2d598f606caa3965195b22f23d5acefeedfcdf056c5b"
		Source = "41badf10ef6f469dd1c3be201aba809f9c42f86ad77d7f83bc3895bfa289c635"
		Source = "d079a266ed2a852c33cdac3df115d163ebbf2c8dae32d935e895cf8193163b13"

	strings:
	/*
		6A 04              push    4               ; MaxCount  <--- this arg is not found in some variants (41bad..) as wcscmp is used instead
		68 08 82 00 10     push    offset Str2     ; ".doc"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp            <--- d07... variant uses a direct call instead
		83 C4 0C           add     esp, 0Ch										<--- when wcscmp is used, this is add esp, 8
		85 C0              test    eax, eax
		0F 84 5B 02 00 00  jz      loc_100017D5
		6A 05              push    5               ; MaxCount
		68 FC 81 00 10     push    offset a_docx   ; ".docx"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
		83 C4 0C           add     esp, 0Ch
		85 C0              test    eax, eax
		0F 84 46 02 00 00  jz      loc_100017D5
		6A 04              push    4               ; MaxCount
		68 F0 81 00 10     push    offset a_docm   ; ".docm"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
		83 C4 0C           add     esp, 0Ch
		85 C0              test    eax, eax
		0F 84 31 02 00 00  jz      loc_100017D5
		6A 04              push    4               ; MaxCount
		68 E4 81 00 10     push    offset a_wpd    ; ".wpd"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
	*/

	$a = {68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 [4] [0-2] 68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 [4] [0-2] 68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 }

	$ext1 = ".wpd" wide nocase
	$ext2 = ".doc" wide nocase
	$ext3 = ".hwp" wide nocase
	
	condition:
		2 of ($ext*) and $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

