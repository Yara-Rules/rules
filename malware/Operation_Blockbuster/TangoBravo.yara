import "pe"

rule TangoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "2aa9cd3a2db2bd9dbe5ee36d9a5fc42b50beca806f9d644f387d5a680a580896"

	strings:
	/*
		50                 push    eax             ; SubStr
		55                 push    ebp             ; Str
		FF D3              call    ebx ; strstr
		83 C4 08           add     esp, 8
		85 C0              test    eax, eax
		75 1A              jnz     short loc_401131
		8A 8E 08 01 00 00  mov     cl, [esi+108h]
		81 C6 08 01 00 00  add     esi, 108h
		47                 inc     edi
		8B C6              mov     eax, esi
		84 C9              test    cl, cl
		75 E2              jnz     short loc_40110C
	*/

	$targetDomainCheck = {5? 5? FF ?? 83 C4 08 85 C0 75 ?? 8? ?? 08 01 00 00 8? ?? 08 01 00 00 4? 8B ?? 84 ?? 75  }

	condition:
		$targetDomainCheck in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
