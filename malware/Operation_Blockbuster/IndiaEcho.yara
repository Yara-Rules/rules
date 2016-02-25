import "pe"

rule IndiaEcho
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "66a21f8c72bb4f314604526e9bf1736f75b06cf37dd3077eb292941b476c3235"

	strings:
	/*
		69 C0 28 01 00 00  imul    eax, 128h
		50                 push    eax             ; size_t
		53                 push    ebx             ; int
		FF B5 AC FD FF FF  push    [ebp+configRecords]; void *
		E8 6E 08 00 00     call    _memset
		8B 85 A4 FC FF FF  mov     eax, [ebp+var_35C.dwRecordCnt]
		69 C0 28 01 00 00  imul    eax, 128h
		50                 push    eax             ; size_t
		8B 85 C4 FE FF FF  mov     eax, [ebp+hMem]
		05 08 01 00 00     add     eax, 108h
		50                 push    eax             ; void *
		FF B5 AC FD FF FF  push    [ebp+configRecords]; void *
		E8 0A 05 00 00     call    _memcpy
		83 C4 18           add     esp, 18h
		8B BD A4 FC FF FF  mov     edi, [ebp+var_35C.dwRecordCnt]
		69 FF 28 01 00 00  imul    edi, 128h
		81 C7 08 01 00 00  add     edi, 108h
	*/

	$a = {
			69 ?? 28 01 00 00 
			5? 
			5? 
			FF B5 [4] 
			E8 [4] 
			8B [5] 
			69 ?? 28 01 00 00 
			50 
			8B [5] 
			(05 08 01 00 00 | 03 ??)
			50 
			FF [5]
			E8 [4] 
			83 C4 ?? 
			8B [5]
			69 ?? 28 01 00 00 
			(81 C7 08 01 00 00 | 03 ??)

		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
