rule apt_hiddencobra_rsakey {

meta:

	description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
	author = "US-CERT"
	url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

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
    url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

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
    url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

strings:

$randomUrlBuilder = { 83 EC 48 53 55 56 57 8B 3D ?? ?? ?? ?? 33 C0 C7 44 24 28 B4 6F 41 00 C7 44 24 2C B0 6F 41 00 C7 44 24 30 AC 6F 41 00 C7 44 24 34 A8 6F 41 00 C7 44 24 38 A4 6F 41 00 C7 44 24 3C A0 6F 41 00 C7 44 24 40 9C 6F 41 00 C7 44 24 44 94 6F 41 00 C7 44 24 48 8C 6F 41 00 C7 44 24 4C 88 6F 41 00 C7 44 24 50 80 6F 41 00 89 44 24 54 C7 44 24 10 7C 6F 41 00 C7 44 24 14 78 6F 41 00 C7 44 24 18 74 6F 41 00 C7 44 24 1C 70 6F 41 00 C7 44 24 20 6C 6F 41 00 89 44 24 24 FF D7 99 B9 0B 00 00 00 F7 F9 8B 74 94 28 BA 9C 6F 41 00 66 8B 06 66 3B 02 74 34 8B FE 83 C9 FF 33 C0 8B 54 24 60 F2 AE 8B 6C 24 5C A1 ?? ?? ?? ?? F7 D1 49 89 45 00 8B FE 33 C0 8D 5C 11 05 83 C9 FF 03 DD F2 AE F7 D1 49 8B FE 8B D1 EB 78 FF D7 99 B9 05 00 00 00 8B 6C 24 5C F7 F9 83 C9 FF 33 C0 8B 74 94 10 8B 54 24 60 8B FE F2 AE F7 D1 49 BF 60 6F 41 00 8B D9 83 C9 FF F2 AE F7 D1 8B C2 49 03 C3 8B FE 8D 5C 01 05 8B 0D ?? ?? ?? ?? 89 4D 00 83 C9 FF 33 C0 03 DD F2 AE F7 D1 49 8D 7C 2A 05 8B D1 C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4 BF 60 6F 41 00 83 C9 FF F2 AE F7 D1 49 BE 60 6F 41 00 8B D1 8B FE 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FB 2B F9 8B CA 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7C 24 60 8D 75 04 57 56 E8 ?? ?? ?? ?? 83 C4 08 C6 04 3E 2E 8B C5 C6 03 00 5F 5E 5D 5B 83 C4 48 C3 }

condition: 
    $randomUrlBuilder
}


rule Malware_Updater
{
meta:
	Author="US-CERT Code Analysis Team"
	Date="2017/08/02"
	Incident="10132963"
	MD5_1="8F4FC2E10B6EC15A01E0AF24529040DD"
	MD5_2="584AC94142F0B7C0DF3D0ADDE6E661ED"
	Info="Malware may be used to update multiple systems with secondary payloads"
	super_rule=1
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10132963.pdf"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = { 8A4C040480F15D80C171884C04044083F8107CEC }
	$s1 = { 8A4D0080F19580E97C884D00454B75F0 }
condition: 
	any of them
} 

rule Unauthorized_Proxy_Server_RAT
{
meta:
	Author="US-CERT Code Analysis Team"
	Incident="10135536"
	MD5_1 = "C74E289AD927E81D2A1A56BC73E394AB"
	MD5_2 = "2950E3741D7AF69E0CA0C5013ABC4209"
	Info="Detects Proxy Server RAT"
	super_rule = 1
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-B_WHITE.PDF"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = {8A043132C288043125FF00000003C299F73D40404900A14440490003D0413BCF72DE5E5FC3}
	$s1 = {8A04318844241432C28804318B44241425FF00000003C299F73D40404900A14440490003D0413BCF72D65E5FC3}
	$s2 = {8A04318844241432C28804318B44241425FF00000003C299F73D5C394100A16039410003D0413BCF72D65E5FC3}
	$s3 = {8A043132C288043125FF00000003C299F73D5C394100A16039410003D0413BCF72DE5E5FC3}
	$s4 = {B91A7900008A140780F29A8810404975F4}
	$s5 = {399FE192769F839DCE9F2A9D2C9EAD9CEB9FD19CA59F7E9F539CEF9F029F969C6C9E5C9D949FC99F}
	$s6 = {8A04318844241432C28804318B44241425FF00000003C299F73D40600910A14460091003D0413BCF72D65E5FC3}
	$s7 = {3C5C75208A41014184C074183C72740C3C7474083C6274043C2275088A41014184C075DC}
	$s8 = {8B063D9534120077353D59341200722E668B4604663DE8037F24}
	$s9 = {8BC88B74241CC1E1052BC88B7C2418C1E1048B5C241403C88D04888B4C242083F9018944240C7523}
	$s10 = {8B063D9034120077353D59341200722E668B4604663DE8037F246685C0}
	$s11 = {30110FB60148FFC102C20FBEC09941F7F94103D249FFC875E7}
	$s12 = {448BE8B84FECC44E41F7EDC1FA038BCAC1E91F03D16BD21A442BEA4183C541}
	$s13 = {8A0A80F9627C2380F9797F1E80F9647C0A80F96D7F0580C10BEB0D80F96F7C0A80F9787F05}
condition:
	any of them
} 

rule NK_SSL_PROXY{
meta:
	Author = "US-CERT Code Analysis Team"
	Date = "2018/01/09"
	MD5_1 = "C6F78AD187C365D117CACBEE140F6230"
	MD5_2 = "C01DC42F65ACAF1C917C0CC29BA63ADC"
	Info= "Detects NK SSL PROXY"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = {8B4C24088A140880F24780C228881408403BC67CEF5E}
	$s1 = {568B74240C33C085F67E158B4C24088A140880EA2880F247881408403BC67CEF5E}
	$s2 = {4775401F713435747975366867766869375E2524736466}
	$s3 = {67686667686A75797566676467667472}
	$s4 = {6D2A5E265E676866676534776572}
	$s5 = {3171617A5853444332337765}
	$s6 = "ghfghjuyufgdgftr"
	$s7 = "q45tyu6hgvhi7^%$sdf"
	$s8 = "m*^&^ghfge4wer"
condition:
	($s0 and $s1 and $s2 and $s3 and $s4 and $s5) or ($s6 and $s7 and $s8)
} 

rule r4_wiper_1
{
meta:
	source = "NCCIC Partner"
	date = "2017-12-12"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$mbr_code = { 33 C0 8E D0 BC 00 7C FB 50 07 50 1F FC BE 5D 7C 33 C9 41 81 F9 00 ?? 74 24 B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 83 55 06 00 EB D5 BE 4D 7C B4 43 B0 00 CD 13 33 C9 BE 5D 7C EB C5 }
	$controlServiceFoundlnBoth = { 83 EC 1C 57 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 44 8B 44 24 24 53 56 6A 24 50 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 1C 8D 4C 24 0C 51 6A 01 56 FF 15 ?? ?? ?? ?? 68 E8 03 00 00 FF 15 ?? ?? ?? ?? 56 FF D3 57 FF D3 5E 5B 33 C0 5F 83 C4 1C C3 33 C0 5F 83 C4 1C C3 }
condition:
	uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and any of them
}

rule r4_wiper_2
{
meta:
	source = "NCCIC Partner"
	date = "2017-12-12"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	// BIOS Extended Write
	$PhysicalDriveSTR = "\\\\.\\PhysicalDrive" wide
	$ExtendedWrite = { B4 43 B0 00 CD 13 }
condition:
	uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and all of them
}
