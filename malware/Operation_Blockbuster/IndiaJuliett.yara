import "pe"

rule IndiaJuliett_1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_writeFile = "a164c0ba0be7c33778c12a6457e9c55a2935564a"


	strings:
		$configFilename = {00 73 63 61 72 64 70 72 76  2E 64 6C 6C 00}
		$suicideScript = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		$commKey = { 10 20 30 40 50 60 70 80 90 11 12 13 1A FF EE 48 }
		/*
		.text:10001850                 push    7530h           ; dwTimeout
		.text:10001855                 lea     eax, [esp+420h+a2]
		.text:10001859                 push    4               ; len
		.text:1000185B                 push    eax             ; a2
		.text:1000185C                 push    esi             ; s
		.text:1000185D                 mov     dword ptr [esp+42Ch+a2], 1000h
		.text:10001865                 call    CommSendWithTimeout
		.text:1000186A                 add     esp, 14h
		.text:1000186D                 cmp     eax, 0FFFFFFFFh
		.text:10001870                 jz      loc_10001915
		.text:10001876                 lea     ecx, [esp+418h+random]
		.text:1000187A                 push    ecx             ; a1
		.text:1000187B                 call    Generate16ByteRandomBuffer
		.text:10001880                 push    0               ; fEncrypt
		.text:10001882                 push    7530h           ; dwTimeout		
		*/
		$handshake = { 68 30 75 00 00 [4] 6A 04 5? 5? C? [3] 00 10 00 00 E8 [7] 83 F8 FF 0F 84 ?? ?? 00 00 8? [3] 5? E8 [4] 6A 00 68 30 75 00 00 }

		/*
			68 00 28 00 00     push    2800h
			56                 push    esi
			E8 38 F7 FF FF     call    sub_401000
			// optionally there is a "add esp, 8" in some variants here
			8D 44 24 28        lea     eax, [esp+270h+NumberOfBytesWritten]
			6A 00              push    0               ; lpOverlapped
			50                 push    eax             ; lpNumberOfBytesWritten
			68 00 28 00 00     push    2800h           ; nNumberOfBytesToWrite
			56                 push    esi             ; lpBuffer
			53                 push    ebx             ; hFile
			FF 15 6C 80 40 00  call    ds:WriteFile
			81 ED 00 28 00 00  sub     ebp, 2800h
			81 C7 00 28 00 00  add     edi, 2800h
			81 C6 00 28 00 00  add     esi, 2800h
		*/
	
		$writeFile = {68 00 28 00 00 5?	E8 [4-7] 8D [3] 6A 00 5? 68 00 28 00 00 5? 5? FF 15 [4] 81 ?? 00 28 00 00 81 ?? 00 28 00 00 81 ?? 00 28 00 00}
				
	condition:
		($configFilename in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size)) or 
			$suicideScript in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size)))
		or
		($handshake in ((pe.sections[pe.section_index(".rsrc")].raw_data_offset)..(pe.sections[pe.section_index(".rsrc")].raw_data_offset + pe.sections[pe.section_index(".rsrc")].raw_data_size)) and 
			$commKey in ((pe.sections[pe.section_index(".rsrc")].raw_data_offset)..(pe.sections[pe.section_index(".rsrc")].raw_data_offset + pe.sections[pe.section_index(".rsrc")].raw_data_size)))
		or
		 $writeFile in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))

}
