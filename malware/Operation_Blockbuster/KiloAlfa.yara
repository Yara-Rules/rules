import "pe"

rule KiloAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		type = "Keylogger"
		SourceForDnscalcVariant1 = "b855d05ef7ab6582864c9b35052a1073a6eb7d0c7e9d97f524ec062715d71321"
		SourceForDnscalcVariant2 = "ddde628be8cd5db768b807510ae1319888e6c4550a5b9a0d54e17b9ec4aaa256"
		
	strings:
		/*
		push    <variable>
		call    GetAsyncKeyState
		cmp     ax, 8001h
		jnz     short loc_4021EE
		push    <variable>             ; a1
		call    AddCharacterToKeyLogBuffer
		add     esp, 4
		
		this block of code is used multiple times in sequence so i'm looking for 5 consecutive blocks
		*/
		$keyxlate = {68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04 68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04 68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04 68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04}
		
	/*
		6A 2A                    push    2Ah
		C6 84 24 C4 00 00 00 D6  mov     [esp+70Ch+var_648], 0D6h
		C6 84 24 C5 00 00 00 E1  mov     [esp+70Ch+var_647], 0E1h
		C6 84 24 C6 00 00 00 BF  mov     [esp+70Ch+var_646], 0BFh
		C6 84 24 C7 00 00 00 C8  mov     [esp+70Ch+var_645], 0C8h
		C6 84 24 C8 00 00 00 C3  mov     [esp+70Ch+var_644], 0C3h
		C6 84 24 C9 00 00 00 BD  mov     [esp+70Ch+var_643], 0BDh
		88 9C 24 CA 00 00 00     mov     [esp+70Ch+var_642], bl
		FF 15 48 5B 40 00        call    GetAsyncKeyState
		66 3D 01 80              cmp     ax, 8001h
		75 20                    jnz     short loc_401696
		8D 94 24 00 01 00 00     lea     edx, [esp+708h+pszOutput]
		8D 84 24 C0 00 00 00     lea     eax, [esp+708h+var_648]
		52                       push    edx             ; pszOutput
		6A 07                    push    7               ; dwLength
		50                       push    eax             ; pszInput
		E8 A3 F9 FF FF           call    DNSCALCDecode
		50                       push    eax             ; a1
		E8 7D FB FF FF           call    AddEntryToKeylogDataBuffer
		83 C4 10                 add     esp, 10h
	*/

	$keyxlateDnscalc1 = {	6A 2A C6 [6] D6 C6 [6] E1 C6 [6] BF C6 [6] C8 C6 [6] C3 C6 [6] BD	88 [6] FF 15 [4] 66 3D 01 80 75 ?? 	8D [6] 8D [6] 5? 6A 07 5? E8 [4] 50 E8 [4] 83 C4 10 }	

	/*
		6A 2A                          push    2Ah
		C7 85 74 FF FF FF D6 E1 BF C8  mov     dword ptr [ebp+var_8C], 0C8BFE1D6h
		66 C7 85 78 FF FF FF C3 BD     mov     [ebp+var_88], 0BDC3h
		88 9D 7A FF FF FF              mov     [ebp+var_86], bl
		FF 15 04 47 41 00              call    GetAsyncKeyState
		BA 01 80 FF FF                 mov     edx, 0FFFF8001h
		66 3B C2                       cmp     ax, dx
		75 1E                          jnz     short loc_4018B0
		8D 85 CC FE FF FF              lea     eax, [ebp+a3]
		50                             push    eax             ; a3
		8D 8D 74 FF FF FF              lea     ecx, [ebp+var_8C]
		6A 07                          push    7               ; dwLength
		51                             push    ecx             ; a1
		E8 89 F7 FF FF                 call    DNSCalcDecode
		50                             push    eax             ; a1
		E8 83 F9 FF FF                 call    RecordStringToLog
		83 C4 10                       add     esp, 10h
	*/

	$keyxlateDnscalc2 = { 6A 2A C7 [5] D6 E1 BF C8 	66 [6] C3 BD 88 [5]	FF 15 [4] BA 01 80 FF FF 66 3B C2 75 ?? 8D [5] 5? 8D [5] 6A 07 5? E8 [4] 50 E8 [4] 83 C4 10 }
	
	condition: 
		$keyxlate in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $keyxlateDnscalc1 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $keyxlateDnscalc2 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
	
}

