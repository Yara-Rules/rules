import "pe"

rule LimaDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "81e6118a6d8bf8994ce93f940059217481bfd15f2757c48c589983a6af54cfcc"

	strings:
	/*
		8B 69 FC           mov     ebp, [ecx-4]
		83 C1 10           add     ecx, 10h
		81 F5 6D 3A 71 58  xor     ebp, 58713A6Dh
		89 2A              mov     [edx], ebp
		33 ED              xor     ebp, ebp
		66 8B 69 F0        mov     bp, [ecx-10h]
		89 6A 04           mov     [edx+4], ebp
		83 C2 08           add     edx, 8
		4F                 dec     edi
		75 E3              jnz     short loc_4026CE
	*/

	$fileDecoder = {8B ?? ?? 83 ?? 10 81 ?? 6D 3A 71 58 89 ?? 33 ?? 66 ?? ?? F0 89 ?? 04 83 ?? 08 4? 75}
		
	/*
		66 81 BC 24 A0 00 00 00 BB 01  cmp     [esp+98h+arg_4], 1BBh
		74 21                          jz      short loc_401BD7
		FF 15 58 30 40 00              call    ds:rand
		99                             cdq
		B9 32 00 00 00                 mov     ecx, 32h
		F7 F9                          idiv    ecx
		8B DA                          mov     ebx, edx
		8D 54 24 5E                    lea     edx, [esp+98h+var_3A]
		53                             push    ebx             ; dwSize
		52                             push    edx             ; pvBuffer
		E8 3F FB FF FF                 call    GenerateRandomBuffer
		83 C4 08                       add     esp, 8
		83 C3 46                       add     ebx, 46h
	*/

	$authenicateBufferGen = {BB 01 74 ?? FF 15 [4] 99 B? 32 00 00 00 F7 ?? 8B ?? 8D [3] 5? 5? E8 [4] 83 C4 08 83 ?? 46}
	
	condition:
		$authenicateBufferGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $fileDecoder in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
