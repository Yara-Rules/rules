rule ROKRAT_loader : TAU DPRK APT

{

meta:

    author = "CarbonBlack Threat Research" //JMyers

    date = "2018-Jan-11"

    description = "Designed to catch loader observed used with ROKRAT malware"
    
    reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"

    rule_version = 1

  	yara_version = "3.7.0"

    TLP = "White"

  	exemplar_hashes = "e1546323dc746ed2f7a5c973dcecc79b014b68bdd8a6230239283b4f775f4bbd"

strings:

	$n1 = "wscript.exe"

	$n2 = "cmd.exe"

	$s1 = "CreateProcess"

	$s2 = "VirtualAlloc"

	$s3 = "WriteProcessMemory"

	$s4 = "CreateRemoteThread"

	$s5 = "LoadResource"

	$s6 = "FindResource"

	$b1 = {33 C9 33 C0 E8 00 00 00 00 5E} //Clear Register, call+5, pop ESI

	$b2 = /\xB9.{3}\x00\x81\xE9?.{3}\x00/ //subtraction for encoded data offset 

  //the above regex could slow down scanning

	$b3 = {03 F1 83 C6 02} //Fix up position

	$b4 = {3E 8A 06 34 90 46} //XOR decode Key

	$b5 = {3E 30 06 46 49 83 F9 00 75 F6} //XOR routine and jmp to code

	//push api hash values plain text

	$hpt_1 = {68 EC 97 03 0C} //api name hash value – Global Alloc

	$hpt_2 = {68 54 CA AF 91} //api name hash value – Virtual Alloc

	$hpt_3 = {68 8E 4E 0E EC} //api name hash value – Load Library

	$hpt_4 = {68 AA FC 0D 7C} //api name hash value – GetProc Addr

	$hpt_5 = {68 1B C6 46 79} //api name hash value – Virtual Protect

	$hpt_6 = {68 F6 22 B9 7C} //api name hash value – Global Free

	//push api hash values encoded XOR 0x13

	$henc_1 = {7B FF 84 10 1F} //api name hash value – Global Alloc

	$henc_2 = {7B 47 D9 BC 82} //api name hash value – Virtual Alloc

	$henc_3 = {7B 9D 5D 1D EC} //api name hash value – Load Library

	$henc_4 = {7B B9 EF 1E 6F} //api name hash value – GetProc Addr

	$henc_5 = {7B 08 D5 55 6A} //api name hash value – Virtual Protect

	$henc_6 = {7B E5 31 AA 6F} //api name hash value – Global Free

condition:

	(1 of ($n*) and 4 of ($s*) and 4 of ($b*)) or all of ($hpt*) or all of ($henc*)

}


rule ROKRAT_payload : TAU DPRK APT

{

meta:

    author = "CarbonBlack Threat Research" //JMyers

    date = "2018-Jan-11"

    description = "Designed to catch loader observed used with ROKRAT malware"
    
    reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"

    rule_version = 1

  	yara_version = "3.7.0"

    TLP = "White"

  	exemplar_hashes = "e200517ab9482e787a59e60accc8552bd0c844687cd0cf8ec4238ed2fc2fa573"

strings:

	$s1 = "api.box.com/oauth2/token" wide

	$s2 = "upload.box.com/api/2.0/files/content" wide

	$s3 = "api.pcloud.com/uploadfile?path=%s&filename=%s&nopartial=1" wide

	$s4 = "cloud-api.yandex.net/v1/disk/resources/download?path=%s" wide

	$s5 = "SbieDll.dll"

	$s6 = "dbghelp.dll"

	$s7 = "api_log.dll"

	$s8 = "dir_watch.dll"

	$s9 = "def_%s.jpg" wide

	$s10 = "pho_%s_%d.jpg" wide

	$s11 = "login=%s&password=%s&login_submit=Authorizing" wide

	$s12 = "gdiplus.dll"

	$s13 = "Set-Cookie:\\b*{.+?}\\n" wide

	$s14 = "charset={[A-Za-z0-9\\-_]+}" wide

condition:

	12 of ($s*)

}

