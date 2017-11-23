rule rc4_stack_key_fallchill
{
meta:
    description = "rc4_stack_key"
	ref = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
strings:
    $stack_key = { 0d 06 09 2a ?? ?? ?? ?? 86 48 86 f7 ?? ?? ?? ?? 0d 01 01 01 ?? ?? ?? ?? 05 00 03 82 41 8b c9 41 8b d1 49 8b 40 08 48 ff c2 88 4c 02 ff ff c1 81 f9 00 01 00 00 7c eb }
condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $stack_key
}

rule success_fail_codes_fallchill
{
meta:
    description = "success_fail_codes"
	ref = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
strings:
    $s0 = { 68 7a 34 12 00 }  
    $s1 = { ba 7a 34 12 00 }  
    $f0 = { 68 5c 34 12 00 }  
    $f1 = { ba 5c 34 12 00 }
condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and (($s0 and $f0) or ($s1 and $f1))
}
