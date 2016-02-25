import "pe"

rule RomeoDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1df2af99fb3b6e31067b06df07b96d0ed0632f85111541a416da9ceda709237c"

	strings:
	/*
		E8 78 00 00 00  call    GenerateRandomBuffer
		33 C0           xor     eax, eax
		8A 4C 04 04     mov     cl, [esp+eax+24h+buffer]
		80 E9 22        sub     cl, 22h
		80 F1 AD        xor     cl, 0ADh
		88 4C 04 04     mov     [esp+eax+24h+buffer], cl
		40              inc     eax
		83 F8 10        cmp     eax, 10h
		7C EC           jl      short loc_1000117A
		6A 01           push    1               ; fEncode
		8D 54 24 08     lea     edx, [esp+28h+buffer]
		6A 10           push    10h             ; dwDataLength
		52              push    edx             ; pvData
		8B CB           mov     ecx, ebx        ; this
		E8 A2 00 00 00  call    CSocket__Send
	*/

	$loginInit = { E8 [4] 33 C0 8A [3] 80 [2] 80 [2] 88 [3] 40 83 F8 10 7C ?? 6A 01 8D [3] 6A 10 5? 8B CB E8	}

	condition:
		$loginInit in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
