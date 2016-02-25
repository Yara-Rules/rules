import "pe"

rule LimaBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Mwsagent.dll"

	strings:
	/*
		83 C4 34        add     esp, 34h
		83 FD 0A        cmp     ebp, 0Ah
		5D              pop     ebp
		5B              pop     ebx
		7E 12           jle     short loc_1000106F
		57              push    edi             ; Src
		C6 07 4D        mov     byte ptr [edi], 4Dh
		C6 47 01 5A     mov     byte ptr [edi+1], 5Ah
		E8 97 01 00 00  call    ManualImageLoad
	*/

	$a = {83 ?? 34 83 ?? 0A [0-2] 7E ?? 5? C6 ?? 4D C6 [2] 5A E8}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
