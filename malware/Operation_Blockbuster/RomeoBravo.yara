import "pe"

rule RomeoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "95314a7af76ec36cfba1a02b67c2b81526a04e3b2f9b8fb9b383ffcbcc5a3d9b"

	strings:
	/*
		E8 D9 FC FF FF  call    SendData
		83 C4 10        add     esp, 10h
		85 C0           test    eax, eax
		74 0A           jz      short loc_10003FE8
		B8 02 00 00 00  mov     eax, 2
		5E              pop     esi
		83 C4 18        add     esp, 18h
		C3              retn
		6A 78           push    78h             ; dwTimeout
		6A 01           push    1               ; fDecode
		8D 54 24 18     lea     edx, [esp+24h+recvData]
		6A 0C           push    0Ch             ; dwLength
		52              push    edx             ; pvBuffer
		56              push    esi             ; skt
		E8 57 FD FF FF  call    RecvData
		83 C4 14        add     esp, 14h
		85 C0           test    eax, eax
		74 0A           jz      short loc_1000400A
		B8 02 00 00 00  mov     eax, 2
	*/

	$a = {
			E8 [4] 
			83 C4 10 
			85 C0 
			74 ?? 
			B? 02 00 00 00 
			5? 
			83 C4 18 
			C3 
			6A 78 
			6A 01 
			8D [3]
			6A 0C 
			5? 
			5? 
			E8 [4]
			83 C4 14 
			85 C0 
			74 ?? 
			B8 02 00 00 00 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}