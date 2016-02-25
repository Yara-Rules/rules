import "pe"

rule LimaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "c9fbad7fc7ff7688776056be3a41714a1f91458a7b16c37c3c906d17daac2c8b"
		Status = "Signature is too loose to be useful."

	strings:
	/*
		33 C0              xor     eax, eax
		66 8B 02           mov     ax, [edx]
		8B E8              mov     ebp, eax
		81 E5 00 F0 FF FF  and     ebp, 0FFFFF000h
		81 FD 00 30 00 00  cmp     ebp, 3000h
		75 0D              jnz     short loc_4019FB
		8B 6C 24 18        mov     ebp, [esp+10h+arg_4]
		25 FF 0F 00 00     and     eax, 0FFFh
		03 C7              add     eax, edi
		01 28              add     [eax], ebp
	*/

	$a = {33 C0 66 [2] 8B ?? 81 ?? 00 F0 FF FF 81 ?? 00 30 00 00 75 ?? 8B [3] 25 FF 0F 00 00 03 C7 01}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
