// rules specific to the winsec malware families
import "pe"

rule RomeoWhiskey_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a8d88714f0bc643e76163d1b8972565e78a159292d45a8218d0ad0754c8f561d"

	strings:
	/*
		FF 15 78 A2 00 10  call    GetTickCount_9
		66 8B C8           mov     cx, ax

		// the next op is a mov or a push/pop depending on the code version
		53                 push    ebx
		8F 45 F4           pop     dword ptr [ebp-0Ch]
		//or
		89 5D F4           mov     dword ptr [ebp+var_C], ebx
		
		
		66 81 F1 40 1C     xor     cx, 1C40h
		66 D1 E9           shr     cx, 1
		81 C1 E0 56 00 00  add     ecx, 56E0h
		0F B7 C9           movzx   ecx, cx
		0F B7 C0           movzx   eax, ax
		81 F1 30 32 00 00  xor     ecx, 3230h
		C1 E0 10           shl     eax, 10h
		0B C8              or      ecx, eax
	*/

	$a = {
			FF 15 [4] 
			66 8B C8 
			[3-4] 
			66 81 F1 40 1C 
			66 D1 E9 
			81 C1 E0 56 00 00 
			0F B7 C9 
			0F B7 C0 
			81 F1 30 32 00 00 
			C1 E0 10 
			0B C8 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}



rule RomeoWhiskey_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "5d21e865d57e9798ac7c14a6ad09c4034d103f3ea993295dcdf8a208ea825ad7"

	strings:
	/*
		FF 15 D8 5B 00 10  call    GetTickCount_9
		0F B7 C0           movzx   eax, ax
		8B C8              mov     ecx, eax
		// skipped: 6A 01              push    1               ; fDecode
		C1 E9 34           shr     ecx, 34h         <--- this value could change
		81 F1 C0 F3 00 00  xor     ecx, 0F3C0h			<--- this value could change
		// skipped: 6A 04              push    4               ; dwLength
		C1 E0 10           shl     eax, 10h
		0B C8              or      ecx, eax
	*/

	$a = {
			FF 15 [4]  
			0F B7 C0
			8B C8
			[2-4] 
			C1 E9 ?? 
			81 F1 [2] 00 00 
			[0-2] 
			C1 E0 10 
			0B C8 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

