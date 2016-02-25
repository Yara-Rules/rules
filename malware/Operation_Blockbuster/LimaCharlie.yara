import "pe"

rule LimaCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_x86 = "6ee6ae79ee1502a11ece81e971a54f189a271be9ec700101a2bd7a21198b94c7"
		Source_x64 = "90ace24eb132c776a6d5bb0451437db21e84601495a2165d75f520af637e71e8"

	strings:
		$misspelling = "Defualt Sleep = %d" wide

	/*
		FF 76 74           push    dword ptr [esi+74h]
		59                 pop     ecx
		50                 push    eax
		8F 86 48 01 00 00  pop     dword ptr [esi+148h]
		85 C0              test    eax, eax
		51                 push    ecx
		8F 86 44 01 00 00  pop     dword ptr [esi+144h]
		75 3D              jnz     short loc_100035F3
		F6 46 56 01        test    byte ptr [esi+56h], 1
		74 0A              jz      short loc_100035C6
	*/

	$x86 = {
			FF ?? 74 
			5? 
			5? 
			8F ?? 48 01 00 00 
			85 C0 
			5? 
			8F ?? 44 01 00 00 
			75 ?? 
			F6 [2] 01 
			74 
		}

	/*
		48 8B 4B 70           mov     rcx, [rbx+70h]
		48 89 8B 60 01 00 00  mov     [rbx+160h], rcx
		48 89 83 68 01 00 00  mov     [rbx+168h], rax
		48 85 C0              test    rax, rax
		75 35                 jnz     short loc_180002372
		F6 43 56 01           test    byte ptr [rbx+56h], 1
		74 07                 jz      short loc_18000234A
	*/

	$x64 = {
			48 [2] 70 
			48 [2] 60 01 00 00 
			48 [2] 68 01 00 00 
			48 85 C0 
			75 ?? 
			F6 [2] 01 
			74 
		}
		
	condition:
		$x86 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $x64 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $misspelling
		
}
