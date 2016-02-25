import "pe"

rule SierraAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "4d4b17ddbcf4ce397f76cf0a2e230c9d513b23065f746a5ee2de74f447be39b9.ex_"

	strings:
	/*
		8D 54 24 08              lea     edx, [esp+128h+argp]
		52                       push    edx             ; argp
		68 7E 66 04 80           push    8004667Eh       ; cmd
		56                       push    esi             ; s
		E8 DB 51 00 00           call    ioctlsocket
		8D 44 24 14              lea     eax, [esp+128h+name]
		6A 10                    push    10h             ; namelen
		50                       push    eax             ; name
		56                       push    esi             ; s
		E8 C8 51 00 00           call    connect
		8B 8C 24 34 01 00 00     mov     ecx, [esp+128h+dwTimeout]
		8D 54 24 0C              lea     edx, [esp+128h+timeout]
		52                       push    edx             ; timeout
		8D 44 24 28              lea     eax, [esp+12Ch+writefds]
		6A 00                    push    0               ; exceptfds
		50                       push    eax             ; writefds
		6A 00                    push    0               ; readfds
		6A 00                    push    0               ; nfds
		89 74 24 3C              mov     [esp+13Ch+writefds.fd_array], esi
		89 7C 24 38              mov     [esp+13Ch+writefds.fd_count], edi
		89 4C 24 20              mov     [esp+13Ch+timeout.tv_sec], ecx
		C7 44 24 24 00 00 00 00  mov     [esp+13Ch+timeout.tv_usec], 0
		E8 92 51 00 00           call    select
		33 C9                    xor     ecx, ecx
		56                       push    esi             ; s
		85 C0                    test    eax, eax
		0F 9F C1                 setnle  cl
		8B F9                    mov     edi, ecx
		E8 7D 51 00 00           call    closesocket
	*/

	$connectTest = { 8D [3] 5? 68 7E 66 04 80 5? E8 [4] 8D [3] 6A 10 5? 5? E8 [4] 8B [6] 8D [3] 5? 8D [3] 6A 00 5? 6A 00 6A 00 
			89 [3] 89 [3] 89 [3] C7 [7] E8 [4] 33 ?? 5? 85 C0 0F 9F ?? 8B ?? E8 }

	/*
		E8 D8 62 00 00                                call    rand
		8B F8                                         mov     edi, eax
		E8 D1 62 00 00                                call    rand
		0F AF F8                                      imul    edi, eax
		E8 C9 62 00 00                                call    rand
		0F AF C7                                      imul    eax, edi
		99                                            cdq
		33 C2                                         xor     eax, edx
		2B C2                                         sub     eax, edx
		33 D2                                         xor     edx, edx
		F7 F6                                         div     esi
		8B FA                                         mov     edi, edx
		57                                            push    edi
		E8 05 13 00 00                                call    sub_402BD0
	*/
	 	$maths = { E8 [4] 8B ?? E8 [4] 0F AF ?? E8 [4] 0F AF ?? 99 33 ?? 2B ?? 33 ?? F7 ?? 8B ?? 5? E8}
		
		$s1 = "recdiscm32.exe"
		$s2 = "\\\\%s\\shared$\\syswow64"
		$s3 = "\\\\%s\\shared$\\system32"

	condition:
		$connectTest in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $maths in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or 3 of ($s*)

}
