// This rule has been modified by @mmorenog @yarules to fix some errors

import "pe"


rule RomeoFoxtrot
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "dropped.bin"
		Source_relativeCalls = "635bebe95671336865f8a546f06bf67ab836ea35795581d8a473ef2cd5ff4a7f"

	strings:
	/*
		C7 44 24 08 01 00 00 00  mov     [esp+128h+argp], 1
		8B 8C 24 30 01 00 00     mov     ecx, dword ptr [esp+128h+wPort]
		C7 44 24 04 00 00 20 03  mov     dword ptr [esp+128h+optval], 3200000h
		51                       push    ecx             ; hostshort
		89 44 24 1C              mov     dword ptr [esp+12Ch+name.sin_addr.S_un], eax
		FF 15 8C 01 FF 7E        call    ds:htons
		6A 06                    push    6               ; protocol
		6A 01                    push    1               ; type
		6A 02                    push    2               ; af
		66 89 44 24 22           mov     [esp+134h+name.sin_port], ax
		66 C7 44 24 20 02 00     mov     [esp+134h+name.sin_family], 2
		FF 15 84 01 FF 7E        call    ds:socket								     <--- this could be a relative call in some variants
		83 F8 FF                 cmp     eax, 0FFFFFFFFh
		89 46 04                 mov     [esi+4], eax
		0F 84 AD 00 00 00        jz      loc_7EFE4C63
		57                       push    edi
		8B 3D 88 01 FF 7E        mov     edi, ds:setsockopt            <---- this line is missing when relative calls are used
		8D 54 24 08              lea     edx, [esp+12Ch+optval]
		6A 04                    push    4               ; optlen
		52                       push    edx             ; optval
		68 02 10 00 00           push    1002h           ; optname
		68 FF FF 00 00           push    0FFFFh          ; level
		50                       push    eax             ; s
		FF D7                    call    edi ; setsockopt								<--- this could be a relative call in some variants
		8B 4E 04                 mov     ecx, [esi+4]
		8D 44 24 08              lea     eax, [esp+12Ch+optval]
		6A 04                    push    4               ; optlen
		50                       push    eax             ; optval
		68 01 10 00 00           push    1001h           ; optname
		68 FF FF 00 00           push    0FFFFh          ; level
		51                       push    ecx             ; s
		FF D7                    call    edi ; setsockopt								<--- this could be a relative call in some variants
	*/

		$connect = { C7 [3] 01 00 00 00 8B [6] C7 [3] 00 00 20 03 5? 89 [3] ( FF 15 | E8 ) [4] 6A 06 6A 01 6A 02 66 [4] 66 [4] 02 00 ( FF 15 | E8 ) [4] 83 F8 FF 89 [2] 0F 84 [4] [0-7] 8D [3] 6A 04 5? 68 02 10 00 00 68 FF FF 00 00 5? ( FF D? | E8 [3] ??) 8B [2] 8D [3] 6A 04 5? 68 01 10 00 00 68 FF FF 00 00 5? ( FF D? | E8 [3] ??) }
		$response = "RESPONSE 200 OK!!!"

	condition:
		$response or 
		$connect in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
