import "pe"

rule RomeoAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "fba0b8bdc1be44d100ac31b864830fcc9d056f1f5ab5486384e09bd088256dd0.file2.bin"

	strings:
	/*
		68 C4 94 41 00     push    offset a0_0_0_0 ; "0.0.0.0"
		56                 push    esi             ; wchar_t *
		E8 1C B4 00 00     call    _wcscpy
		83 C6 28           add     esi, 28h
		83 C4 08           add     esp, 8
		81 FE E8 CD 41 00  cmp     esi, offset unk_41CDE8
		7C E7              jl      short loc_4039DA
	*/

	$zeroIPLoader = {68 [4] 56 E8 [4] 83 C6 28 83 C4 08 81 FE [4] 7C E?}
		


		// push    esi                              
		// mov     esi, [esp+4+a1]                  
		// test    esi, esi                         
		// jle     short loc_403FEB                 
		// push    edi                              
		// mov     edi, ds:Sleep                    
		// push    0EA60h          ; dwMilliseconds 
		// call    edi ; Sleep                      
		// dec     esi                              
		// jnz     short loc_403FE0                 
		// pop     edi                              
		// pop     esi                              
		// retn                                     
		$sleeper  = {5? 8B [3] 85 ?? 7E ?? 5? 8B 3D [4]  68 [4] FF ??  4? 75 ??	5? 5? C3 }
			
		$xercesc = "xercesc"
		
	condition:
		($sleeper in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $zeroIPLoader in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size)))
		and not $xercesc
}


