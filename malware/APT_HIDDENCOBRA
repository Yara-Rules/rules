rule apt_hiddencobra_rsakey {

meta:

	description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
	author = "US-CERT"
	url = "https://www.us-cert.gov/ncas/alerts/TA17-164A?platform=hootsuite"

strings:

    $rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94

    A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77

    48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39

    73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2

    AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED

    39 3F FA D0 AD 3D D9 C5 3D 28 EF 3D 67 B1 E0 68

    3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13

    B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}

condition: 
	any of them
}


rule apt_hiddencobra_binaries {

meta:

    description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
    author = "US-CERT"
    url = "https://www.us-cert.gov/ncas/alerts/TA17-164A?platform=hootsuite"

strings:

   $STR1 = "Wating" wide ascii

   $STR2 = "Reamin" wide ascii

   $STR3 = "laptos" wide ascii

condition: 
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 2 of them
}


rule apt_hiddencobra_urlbuilder {

meta:

    description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
    author = "US-CERT"
    url = "https://www.us-cert.gov/ncas/alerts/TA17-164A?platform=hootsuite"

strings:

$randomUrlBuilder = { 83 EC 48 53 55 56 57 8B 3D ?? ?? ?? ?? 33 C0 C7 44 24 28 B4 6F 41 00 C7 44 24 2C B0 6F 41 00 C7 44 24 30 AC 6F 41 00 C7 44 24 34 A8 6F 41 00 C7 44 24 38 A4 6F 41 00 C7 44 24 3C A0 6F 41 00 C7 44 24 40 9C 6F 41 00 C7 44 24 44 94 6F 41 00 C7 44 24 48 8C 6F 41 00 C7 44 24 4C 88 6F 41 00 C7 44 24 50 80 6F 41 00 89 44 24 54 C7 44 24 10 7C 6F 41 00 C7 44 24 14 78 6F 41 00 C7 44 24 18 74 6F 41 00 C7 44 24 1C 70 6F 41 00 C7 44 24 20 6C 6F 41 00 89 44 24 24 FF D7 99 B9 0B 00 00 00 F7 F9 8B 74 94 28 BA 9C 6F 41 00 66 8B 06 66 3B 02 74 34 8B FE 83 C9 FF 33 C0 8B 54 24 60 F2 AE 8B 6C 24 5C A1 ?? ?? ?? ?? F7 D1 49 89 45 00 8B FE 33 C0 8D 5C 11 05 83 C9 FF 03 DD F2 AE F7 D1 49 8B FE 8B D1 EB 78 FF D7 99 B9 05 00 00 00 8B 6C 24 5C F7 F9 83 C9 FF 33 C0 8B 74 94 10 8B 54 24 60 8B FE F2 AE F7 D1 49 BF 60 6F 41 00 8B D9 83 C9 FF F2 AE F7 D1 8B C2 49 03 C3 8B FE 8D 5C 01 05 8B 0D ?? ?? ?? ?? 89 4D 00 83 C9 FF 33 C0 03 DD F2 AE F7 D1 49 8D 7C 2A 05 8B D1 C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4 BF 60 6F 41 00 83 C9 FF F2 AE F7 D1 49 BE 60 6F 41 00 8B D1 8B FE 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FB 2B F9 8B CA 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7C 24 60 8D 75 04 57 56 E8 ?? ?? ?? ?? 83 C4 08 C6 04 3E 2E 8B C5 C6 03 00 5F 5E 5D 5B 83 C4 48 C3 }

condition: 
    $randomUrlBuilder
}
