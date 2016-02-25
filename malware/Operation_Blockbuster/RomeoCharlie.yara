import "pe"

rule RomeoCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a82108ef7115931b3fbe1fab99448c4139e22feda27c1b1d29325710671154e8"

	strings:
		$auth1 = "Success - Accept Auth"
		$auth2 = "Fail - Accept Auth"

	/*
		81 E3 FF FF 00 00  and     ebx, 0FFFFh
		8B EB              mov     ebp, ebx
		57                 push    edi
		C1 EE 10           shr     esi, 10h
		81 E5 FF FF 00 00  and     ebp, 0FFFFh
		8B FE              mov     edi, esi
		8B C5              mov     eax, ebp
		81 E7 FF FF 00 00  and     edi, 0FFFFh
		C1 E0 10           shl     eax, 10h
		6A 00              push    0               ; _DWORD
		0B C7              or      eax, edi
		6A 00              push    0               ; _DWORD
		50                 push    eax             ; _DWORD
		68 10 14 11 71     push    offset sub_71111410; _DWORD
		6A 00              push    0               ; _DWORD
		6A 00              push    0               ; _DWORD
		FF 15 5C 8E 12 71  call    CreateThread_0
		C1 E7 10           shl     edi, 10h
	*/

	$startupRelayThreads = {
			81 ?? FF FF 00 00 
			8B ?? 
			5? 
			C1 ?? 10 
			81 ?? FF FF 00 00 
			8B ?? 
			8B ?? 
			81 ?? FF FF 00 00 
			C1 ?? 10 
			6A 00 
			0B ?? 
			6A 00 
			50 
			68 [4] 
			6A 00 
			6A 00 
			FF 15 [4] 
			C1 ?? 10 
		}

	/*
	source: 641808833ad34f2e5143001c8147d779dbfd2a80a80ce0cfc81474d422882adb
		25 00 20 00 00     and     eax, 2000h
		3D 00 20 00 00     cmp     eax, 2000h
		0F 94 C1           setz    cl
		81 E2 80 00 00 00  and     edx, 80h
		33 C0              xor     eax, eax
		80 FA 80           cmp     dl, 80h
		0F 94 C0           setz    al
		03 C8              add     ecx, eax
		33 D2              xor     edx, edx
		83 F9 01           cmp     ecx, 1
	*/

	$crypto = {
			2? 00 20 00 00 
			3? 00 20 00 00 
			0F [2] 
			81 ?? 80 00 00 00 
			33 ?? 
			80 ?? 80 
			0F [2] 
			03 ?? 
			33 ?? 
			83 ?? 01 
		}

	condition:
		all of ($auth*) 
		or $startupRelayThreads in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $crypto in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
