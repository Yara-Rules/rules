import "pe"


rule RomeoJuliettMikeTwo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "819722ba1c5b9d0b360c54cbdd3811d0cac1a9230720b3ed4815f78bcacb3653_d1ba9ba2987f59d99ce4bf09393c0521c4d1f2961c5aeed4e0bf86e78303d27c"

	strings:
	/*
		81 7C 24 24 33 27 00 00  cmp     [esp+1Ch+dwBytesToRead], 2733h
		75 7F                    jnz     short loc_10002B74
		8D 54 24 14              lea     edx, [esp+1Ch+var_8]
		52                       push    edx             ; Time
		FF 15 5C 11 02 10        call    ds:time
		8B 44 24 14              mov     eax, [esp+20h+var_C]
		83 C4 04                 add     esp, 4
		8B C8                    mov     ecx, eax
		40                       inc     eax
		83 F9 64                 cmp     ecx, 64h
	*/

	$recvFunc = { 81 [3] 33 27 00 00 75 ?? 8D [3] 5? FF 15 [4] 8B [3] 83 ?? 04 8B ?? 4? 83 ?? 64 }

	/*
		E8 74 31 00 00     call    GetStringByIndex
		8B 7C 24 14        mov     edi, [esp+0Ch+dwFuncIndex]
		8B F0              mov     esi, eax
		57                 push    edi             ; index
		E8 68 31 00 00     call    GetStringByIndex
		83 C4 08           add     esp, 8
		85 F6              test    esi, esi
		74 21              jz      short loc_10001040
		85 C0              test    eax, eax
		74 1D              jz      short loc_10001040
		56                 push    esi             ; lpLibFileName
		FF 15 2C 10 02 10  call    ds:LoadLibraryA
		57                 push    edi             ; index
		8B F0              mov     esi, eax
		E8 4E 31 00 00     call    GetStringByIndex
		83 C4 04           add     esp, 4
		50                 push    eax             ; lpProcName
		56                 push    esi             ; hModule
		FF 15 5C 10 02 10  call    ds:GetProcAddress
	*/

	$apiLoader = { E8 [4] 8B [3] 8B ?? 5? E8 [4] 83 C4 08 85 ?? 74 ?? 85 C0 74 ?? 5? FF 15 [4] 5? 8B ?? E8 [4] 83 C4 04 5? 5? FF 15 }

	/*
		68 B8 0B 00 00           push    0BB8h           ; dwMilliseconds
		FF 15 18 10 02 10        call    ds:Sleep
		6A 01                    push    1               ; dwTimeout
		8D 4C 24 10              lea     ecx, [esp+4C0h+peerEntries]
		68 B0 04 00 00           push    4B0h            ; dwBytesToRead
		51                       push    ecx             ; pvRecvBuffer
		8B CE                    mov     ecx, esi        ; this
		C7 44 24 14 B0 04 00 00  mov     [esp+4C8h+Memory], 4B0h
		E8 25 F4 FF FF           call    CClientConnection__RecvData
		83 F8 FF                 cmp     eax, 0FFFFFFFFh
	*/

	$recvPeers = { 68 B8 0B 00 00 FF 15 [4] 6A 01 [0-4] 68 B0 04 00 00 51 8B ?? [1-4] B0 04 00 00 E8 [4] 83 F8 FF	}		
		
	$logFileName = "KBD_%%s_%%02d%%02d%%02d%%02d%%02d.CAT"
	
	condition:
		$recvFunc in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $apiLoader in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $recvPeers in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $logFileName
}
