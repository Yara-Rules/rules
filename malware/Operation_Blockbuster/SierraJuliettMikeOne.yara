import "pe"

rule SierraJuliettMikeOne
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
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
		
	condition:
		$commKey in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
		and $handshake in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))

}