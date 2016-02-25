import "pe"

rule WhiskeyAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1c66e67a8531e3ff1c64ae57e6edfde7bef2352d.ex_"

	strings:
	/*
		E8 77 07 00 00     call    _rand
		B1 FB              mov     cl, 0FBh
		F6 E9              imul    cl
		88 44 34 08        mov     [esp+esi+10008h+randomData], al
		46                 inc     esi
		81 FE 00 00 01 00  cmp     esi, 10000h
		7C EA              jl      short loc_402E8D
	*/

	$randomBuffer = {E8 [4] B1 ?? F6 E9 88 [3] 4? 81 ?? 00 00 01 00 7C}

	/*
		89 58 09              mov     [eax+9], ebx
		C7 40 65 00 00 02 00  mov     dword ptr [eax+65h], 20000h
		C7 40 15 04 00 00 00  mov     dword ptr [eax+15h], 4
		C6 40 08 08           mov     byte ptr [eax+8], 8
		C7 40 04 00 02 00 00  mov     dword ptr [eax+4], 200h
		89 18                 mov     [eax], ebx
		89 58 0D              mov     [eax+0Dh], ebx
		C7 40 11 01 00 00 00  mov     dword ptr [eax+11h], 1
		89 58 69              mov     [eax+69h], ebx
		89 58 19              mov     [eax+19h], ebx
		B8 01 00 00 00        mov     eax, 1
	*/
	$mbrDiskInfo = {89 ?? 09 C7 ?? 65 00 00 02 00 C7 ?? 15 04 00 00 00 C6 ?? 08 08 C7 ?? 04 00 02 00 00 89 ?? 89 ?? 0D C7 ?? 11 01 00 00 00 89 ?? 69 89 ?? 19 B8 01 00 00 00}
		

		// the replacement MBRs in both encoded (XOR 0x53) and decoded form		
		$mbrReplacement_Decoded = { B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 }
		$mbrReplacement_Encoded = { E7 10 E3 53 9E 40 AD 91 D3 A9 D7 2F A0 E1 D3 EC 36 2F D2 56 53 57 D0 06 51 53 D0 06 57 53 }
	
		$licKey = "99E2428CCA4309C68AAF8C616EF3306582A64513E55C786A864BC83DAFE0C78585B692047273B0E55275102C664C5217E76B8E67F35FCE385E4328EE1AD139EA6AA26345C4F93000DBBC7EF1579D4F"
		
	condition:
		$licKey or $mbrReplacement_Decoded or $mbrReplacement_Encoded
		or $randomBuffer in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $mbrDiskInfo in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
