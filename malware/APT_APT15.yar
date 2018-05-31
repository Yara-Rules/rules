import "pe"

rule clean_apt15_patchedcmd{
	meta:
		author = "Ahmed Zaki"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
	strings:
	    $ = "eisableCMD" wide
	    $ = "%WINDOWS_COPYRIGHT%" wide
	    $ = "Cmd.Exe" wide
	    $ = "Windows Command Processor" wide
	condition:
        	all of them
}

rule malware_apt15_royalcli_1{
	meta:
    description = "Generic strings found in the Royal CLI tool"
    reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		author = "David Cannings"
		sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"

	strings:
	    $ = "%s~clitemp%08x.tmp" fullword
	    $ = "qg.tmp" fullword
	    $ = "%s /c %s>%s" fullword
	    $ = "hkcmd.exe" fullword
	    $ = "%snewcmd.exe" fullword
	    $ = "%shkcmd.exe" fullword
	    $ = "%s~clitemp%08x.ini" fullword
	    $ = "myRObject" fullword
	    $ = "myWObject" fullword
	    $ = "10 %d %x\x0D\x0A"
	    $ = "4 %s  %d\x0D\x0A"
	    $ = "6 %s  %d\x0D\x0A"
	    $ = "1 %s  %d\x0D\x0A"
	    $ = "3 %s  %d\x0D\x0A"
	    $ = "5 %s  %d\x0D\x0A"
	    $ = "2 %s  %d 0 %d\x0D\x0A"
	    $ = "2 %s  %d 1 %d\x0D\x0A"
	    $ = "%s file not exist" fullword

	condition:
	    5 of them
}

rule malware_apt15_royalcli_2{
	meta:
    author = "Nikolaos Pantazopoulos"
    description = "APT15 RoyalCli backdoor"
    reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$string1 = "%shkcmd.exe" fullword
		$string2 = "myRObject" fullword
		$string3 = "%snewcmd.exe" fullword
		$string4 = "%s~clitemp%08x.tmp" fullword
		$string5 = "hkcmd.exe" fullword
		$string6 = "myWObject" fullword
	condition:
		uint16(0) == 0x5A4D and 2 of them
}

rule malware_apt15_bs2005{
	meta:
		author	=	"Ahmed Zaki"
		md5	=	"ed21ce2beee56f0a0b1c5a62a80c128b"
		description	=	"APT15 bs2005"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
   	strings:
		$ = "%s&%s&%s&%s"  wide ascii
		$ = "%s\\%s"  wide ascii
		$ = "WarOnPostRedirect"  wide ascii fullword
		$ = "WarnonZoneCrossing"  wide ascii fullword
		$ = "^^^^^" wide ascii fullword
			/*
				"%s" /C "%s > "%s\tmp.txt" 2>&1 "     
			*/
		$ =  /"?%s\s*"?\s*\/C\s*"?%s\s*>\s*\\?"?%s\\(\w+\.\w+)?"\s*2>&1\s*"?/ 
		$ ="IEharden" wide ascii fullword
		$ ="DEPOff" wide ascii fullword
		$ ="ShownVerifyBalloon" wide ascii fullword
		$ ="IEHardenIENoWarn" wide ascii fullword
   	condition:
		(uint16(0) == 0x5A4D and 5 of them) or 
		( uint16(0) == 0x5A4D and 3 of them and 
		( pe.imports("advapi32.dll", "CryptDecrypt") and pe.imports("advapi32.dll", "CryptEncrypt") and
		pe.imports("ole32.dll", "CoCreateInstance")))}

rule malware_apt15_royaldll{
	meta:
		author = "David Cannings"
		description = "DLL implant, originally rights.dll and runs as a service"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"          
	strings:
	    /*
	      56                push    esi
	      B8 A7 C6 67 4E    mov     eax, 4E67C6A7h
	      83 C1 02          add     ecx, 2
	      BA 04 00 00 00    mov     edx, 4
	      57                push    edi
	      90                nop
	    */
	    // JSHash implementation (Justin Sobel's hash algorithm)
		$opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }

	    /*
	      0F B6 1C 03       movzx   ebx, byte ptr [ebx+eax]
	      8B 55 08          mov     edx, [ebp+arg_0]
	      30 1C 17          xor     [edi+edx], bl
	      47                inc     edi
	      3B 7D 0C          cmp     edi, [ebp+arg_4]
	      72 A4             jb      short loc_10003F31
	    */
	    // Encode loop, used to "encrypt" data before DNS request
		$opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }

	    /*
	      68 88 13 00 00    push    5000 # Also seen 3000, included below
	      FF D6             call    esi ; Sleep
	      4F                dec     edi
	      75 F6             jnz     short loc_10001554
	    */
	    // Sleep loop
		$opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }

	    // Generic strings
	    $ = "Nwsapagent" fullword
	    $ = "\"%s\">>\"%s\"\\s.txt"
	    $ = "myWObject" fullword
	    $ = "del c:\\windows\\temp\\r.exe /f /q"
	    $ = "del c:\\windows\\temp\\r.ini /f /q"
	condition:
		3 of them
}

rule malware_apt15_royaldll_2	{
	meta:
		author	=	"Ahmed Zaki"
		sha256	=	"bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
		description	=	"DNS backdoor used by APT15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		    $= "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide ascii 
		    $= "netsvcs" wide ascii fullword
		    $= "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide ascii fullword
		    $= "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
		    $= "myWObject" wide ascii 
	condition:
		uint16(0) == 0x5A4D and all of them
		and pe.exports("ServiceMain")
		and filesize > 50KB and filesize < 600KB
}

rule malware_apt15_exchange_tool {
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$s1= "subjectname" fullword
		$s2= "sendername" fullword
		$s3= "WebCredentials" fullword
		$s4= "ExchangeVersion"	fullword
		$s5= "ExchangeCredentials"	fullword
		$s6= "slfilename"	fullword
		$s7= "EnumMail"	fullword
		$s8= "EnumFolder"	fullword
		$s9= "set_Credentials"	fullword
		$s10 = "/de" wide
		$s11 = "/sn" wide
		$s12 = "/sbn" wide
		$s13 = "/list" wide
		$s14 = "/enum" wide
		$s15 = "/save" wide
		$s16 = "/ao" wide
		$s17 = "/sl" wide
		$s18 = "/v or /t is null" wide
		$s19 = "2007" wide
		$s20 = "2010" wide
		$s21 = "2010sp1" wide
		$s22 = "2010sp2" wide
		$s23 = "2013" wide
		$s24 = "2013sp1" wide
	condition:
		uint16(0) == 0x5A4D and 15 of ($s*)
}

rule malware_apt15_generic {
	meta:
		author = "David Cannings"
		description = "Find generic data potentially relating to AP15 tools"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
	    // Appears to be from copy/paste code
		$str01 = "myWObject" fullword
		$str02 = "myRObject" fullword

	    /*
	      6A 02             push    2               ; dwCreationDisposition
	      6A 00             push    0               ; lpSecurityAttributes
	      6A 00             push    0               ; dwShareMode
	      68 00 00 00 C0    push    0C0000000h      ; dwDesiredAccess
	      50                push    eax             ; lpFileName
	      FF 15 44 F0 00 10 call    ds:CreateFileA
	    */
	    // Arguments for CreateFileA
		$opcodes01 = { 6A (02|03) 6A 00 6A 00 68 00 00 00 C0 50 FF 15 }
  	condition:
		2 of them
}
