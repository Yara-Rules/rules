// sigs for the various cross-family codes
import "pe"

rule Caracachs: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		B9 10 00 00 00     mov     ecx, 10h        ; ecx = 16
		8B 06              mov     eax, [esi]      ; eax = lastValue
		C1 EA 10           shr     edx, 10h        ; edx = val >> 16
		81 E2 FF 7F 00 00  and     edx, 7FFFh      ; edx = (val >> 16) & 0x7FFF
		03 C2              add     eax, edx        ; eax = ((val >> 16) & 0x7FFF) + lastValue
		8B D0              mov     edx, eax        ; edx = ((val >> 16) & 0x7FFF) + lastValue
		8B F8              mov     edi, eax        ; edi = ((val >> 16) & 0x7FFF) + lastValue
		83 E2 0F           and     edx, 0Fh        ; edx = (((val >> 16) & 0x7FFF) + lastValue) & 0xF
		2B CA              sub     ecx, edx        ; ecx = 16 - ((((val >> 16) & 0x7FFF) + lastValue)) & 0xF
		D3 EF              shr     edi, cl         ; edi = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		8B CA              mov     ecx, edx        ; ecx = (((val >> 16) & 0x7FFF) + lastValue) & 0xF
		D3 E0              shl     eax, cl         ; eax = (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		0B F8              or      edi, eax        ; edi = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF) | (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		89 3E              mov     [esi], edi      ; pLastValue = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF) | (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
	*/

	$a = {B? 10 00 00 00 8B ?? C1 ?? 10 81 ?? FF 7F 00 00 03 ?? 8B ?? 8B ?? 83 ?? 0F 2B ?? D3 ?? 8B ?? D3 ?? 0B ?? 	89 ?? 	}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule StringDotSimplified: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		F3 AB     rep stosd
		80 3A 00  cmp     byte ptr [edx], 0
		74 15     jz      short loc_404170
		8A 02     mov     al, [edx]
		3C 2E     cmp     al, 2Eh
		74 07     jz      short loc_404168
		3C 20     cmp     al, 20h
		74 03     jz      short loc_404168
		88 06     mov     [esi], al
		46        inc     esi
	*/

	$a = {	F3 AB 	80 ?? 00 	74 ?? 	8A 02 	3C 2E 	74 ?? 	3C 20 	74 ?? 	88 06 	46 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule FakeTLS_ServerHelloGetSelectedCipher: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		24 10           and     al, 10h
		0C 10           or      al, 10h
		89 07           mov     [edi], eax
		66 8B 44 24 14  mov     ax, [esp+0Ch+wCipherSuiteID]
		66 3D 00 C0     cmp     ax, 0C000h
		73 34           jnb     short loc_4067C1
		66 2D 35 00     sub     ax, 35h
		66 F7 D8        neg     ax
		1B C0           sbb     eax, eax
		24 80           and     al, 80h
		05 00 01 00 00  add     eax, 100h
		8B D8           mov     ebx, eax
		53              push    ebx             ; hostshort
	*/

	$a = {	24 10 	0C 10 	89 ?? 	66 8? [3] 66 3? 00 C0 73 ?? 66 2? 35 00 66 F7 ?? 1B ?? 	2? 80 0? 00 01 00 00 8B ?? 5? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule XORDecodeA7: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		8A 04 17  mov     al, [edi+edx]
		8B FB     mov     edi, ebx
		34 A7     xor     al, 0A7h
		46        inc     esi
		88 02     mov     [edx], al
		83 C9 FF  or      ecx, 0FFFFFFFFh
		33 C0     xor     eax, eax
		42        inc     edx
		F2 AE     repne scasb
		F7 D1     not     ecx
		49        dec     ecx
		3B F1     cmp     esi, ecx
	*/

	$a = {	8A [2] 	8B ??	34 A7 	46 88 ?? 83 ?? FF 33 ?? 4? F2 AE F7 ?? 	4? 3B ?? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule DynamicAPILoading: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		83 C4 04           add     esp, 4
		50                 push    eax             ; lpProcName
		56                 push    esi             ; hModule
		FF 15 20 F0 40 00  call    ds:GetProcAddress
		68 A8 0C 41 00     push    offset aLo_adlIbr_arYw; "Lo.adL ibr.ar yW"
		A3 DC 3E 41 00     mov     GetProcAddress_0, eax
		E8 7D FF FF FF     call    CleanupString
		83 C4 04           add     esp, 4
		50                 push    eax             ; _DWORD
		56                 push    esi             ; _DWORD
		FF 15 DC 3E 41 00  call    GetProcAddress_0
		68 94 0C 41 00     push    offset aLoad_LibR_arYa; "Load. Lib r.ar yA"
		A3 D4 3E 41 00     mov     LoadLibraryW, eax
		E8 63 FF FF FF     call    CleanupString
		83 C4 04           add     esp, 4
		50                 push    eax             ; _DWORD
		56                 push    esi             ; _DWORD
		FF 15 DC 3E 41 00  call    GetProcAddress_0
		68 80 0C 41 00     push    offset a_frE_eliBr_arY; ".Fr e.eLi br.ar y"
		A3 D8 3E 41 00     mov     LoadLibraryA_0, eax
		E8 49 FF FF FF     call    CleanupString
	*/

	$a = {	83 C4 ?? 5? 5? 	FF 15 [4] 68 [4] A3 [4]	E8 [4]	83 C4 ?? 5? 5? 	FF 15 [4] 68 [4] A3 [4]	E8 [4] 83 C4 ?? 5?  5? 	FF 15 [4] 68 [4] A3 [4]	E8}


	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule DNSCalcStyleEncodeAndDecode: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "975522bc3e07f7aa2c4a5457e6cc16c49a148b9f731134b8971983225835577e"

	strings:
	/*
		8A 10     mov     dl, [eax]
		80 F2 73  xor     dl, 73h					<--- for decoding and encoding, this and
		80 EA 3A  sub     dl, 3Ah					<--- this could be reversed, but the sig holds since both are 0x80
		88 10     mov     [eax], dl
		40        inc     eax
		49        dec     ecx
		75 F2     jnz     short loc_1000403C
	*/

	$a = {8A ?? 80 ?? ?? 80 ?? ?? 88 ?? 4? 4? 75 ?? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule GenerateTLSClientHelloPacket_Test: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		25 07 00 00 80  and     eax, 80000007h
		79 05           jns     short loc_405EC8; um, nope.. this will always happen
		48              dec     eax
		83 C8 F8        or      eax, 0FFFFFFF8h
		40              inc     eax
	*/

	$a = {25 07 00 00 80 79 ?? 4? 	83 ?? F8 4? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule RC4SboxKeyGen: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin"

	strings:
	/*
		8A 4C 04 08        mov     cl, [esp+eax+108h+sbox]; cl = sbox[i]
		8B D0              mov     edx, eax
		81 E2 0F 00 00 80  and     edx, 8000000Fh  ; i % 16
		79 05              jns     short loc_10003AC8; dl = key[i & 16]
		4A                 dec     edx
		83 CA F0           or      edx, 0FFFFFFF0h
		42                 inc     edx
	*/

	$a = {	8A [3] 	8B ?? 	81 ?? 0F 00 00 80 79 ?? 4? 83 ?? F0 4? 	}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule RandomTimestampGenerator: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin joanap baseline sample"

	strings:
	/*
		66 81 44 24 0C FE FF  add     [esp+1Ch+SystemTime.wYear], 0FFFEh
		FF D6                 call    esi ; rand
		99                    cdq
		B9 0C 00 00 00        mov     ecx, 0Ch
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 0E        mov     [esp+1Ch+SystemTime.wMonth], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 1C 00 00 00        mov     ecx, 1Ch
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 12        mov     [esp+1Ch+SystemTime.wDay], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 17 00 00 00        mov     ecx, 17h
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 14        mov     [esp+1Ch+SystemTime.wHour], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 3B 00 00 00        mov     ecx, 3Bh
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 16        mov     [esp+1Ch+SystemTime.wMinute], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 3B 00 00 00        mov     ecx, 3Bh
		F7 F9                 idiv    ecx
	*/

	$a = {	66 81 [3] FE FF FF [1-4] 99 B9 0C 00 00 00 F7 [1-4] 42 	66 89 [3]  FF D6 99 B9 1C 00 00 00 F7 [1-4] 42 	66 89 [3] FF D6 99 B9 17 00 00 00 F7 [1-4] 42 66 89 [3] FF D6 99 B9 3B 00 00 00 F7 [1-4] 42 66 89 [3] FF D6 99 	B9 3B 00 00 00 	F7 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule CPUInfoExtraction
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd10010_296fcc9d611ca1b8f8288192d6d854cf4072853010cc65cb0c7f958626999fbd.bin"

	strings:
	/*
		68 00 00 00 80     push    80000000h       ; a2
		8B 02              mov     eax, [edx]
		8B 4A 04           mov     ecx, [edx+4]
		89 4C 24 10        mov     [esp+2Ch+var_1C], ecx
		8B 4A 08           mov     ecx, [edx+8]
		89 4C 24 14        mov     [esp+2Ch+var_18], ecx
		8B 4A 0C           mov     ecx, [edx+0Ch]
		8D 54 24 1C        lea     edx, [esp+2Ch+var_10]
		89 8E 70 03 00 00  mov     [esi+370h], ecx
		52                 push    edx             ; a1
		8B CE              mov     ecx, esi
		89 86 6C 03 00 00  mov     [esi+36Ch], eax
		E8 29 FF FF FF     call    GetCPUIDValues
		8B C8              mov     ecx, eax
		8B 01              mov     eax, [ecx]
		3D 00 00 00 80     cmp     eax, 80000000h
		8B 51 04           mov     edx, [ecx+4]
	*/

	$a = {68 00 00 00 80 8B ?? 8B ?? 04 89 [3] 8B ?? 08 89 [3] 8B ?? 0C 8D [3] 89 [5] 5? 8B ?? 89 [5] E8 [4] 8B ?? 8B ?? 	3D 00 00 00 80 8B ?? 04 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
