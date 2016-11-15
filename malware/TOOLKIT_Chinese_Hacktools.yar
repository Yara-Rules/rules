rule mswin_check_lm_group {
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"
	strings:
		$s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
		$s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s3 = "-D    default user Domain" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule WAF_Bypass {
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"
	strings:
		$s1 = "Email: blacksplitn@gmail.com" fullword wide
		$s2 = "User-Agent:" fullword wide
		$s3 = "Send Failed.in RemoteThread" fullword ascii
		$s4 = "www.example.com" fullword wide
		$s5 = "Get Domain:%s IP Failed." fullword ascii
		$s6 = "Connect To Server Failed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 7992KB and 5 of them
}

rule Guilin_veterans_cookie_spoofing_tool {
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
	strings:
		$s0 = "kernel32.dll^G" fullword ascii
		$s1 = "\\.Sus\"B" fullword ascii
		$s4 = "u56Load3" fullword ascii
		$s11 = "O MYTMP(iM) VALUES (" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}

rule MarathonTool {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}

rule PLUGIN_TracKid {
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
	strings:
		$s0 = "E-mail: cracker_prince@163.com" fullword ascii
		$s1 = ".\\TracKid Log\\%s.txt" fullword ascii
		$s2 = "Coded by prince" fullword ascii
		$s3 = "TracKid.dll" fullword ascii
		$s4 = ".\\TracKid Log" fullword ascii
		$s5 = "%08x -- %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule Pc_pc2015 {
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 309KB and all of them
}

rule sekurlsa {
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
		$s3 = "SECURITY\\Policy\\Secrets" fullword wide
		$s4 = "Injection de donn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule mysqlfast {
	meta:
		description = "Chinese Hacktool Set - file mysqlfast.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"
	strings:
		$s2 = "Invalid password hash: %s" fullword ascii
		$s3 = "-= MySql Hash Cracker =- " fullword ascii
		$s4 = "Usage: %s hash" fullword ascii
		$s5 = "Hash: %08lx%08lx" fullword ascii
		$s6 = "Found pass: " fullword ascii
		$s7 = "Pass not found" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 900KB and 4 of them
}

rule DTools2_02_DTools {
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
	strings:
		$s0 = "kernel32.dll" ascii
		$s1 = "TSETPASSWORDFORM" fullword wide
		$s2 = "TGETNTUSERNAMEFORM" fullword wide
		$s3 = "TPORTFORM" fullword wide
		$s4 = "ShellFold" fullword ascii
		$s5 = "DefaultPHotLigh" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule dll_PacketX {
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		score = 50
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"
	strings:
		$s9 = "[Failed to load winpcap packet.dll." wide
		$s10 = "PacketX Version" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}

rule SqlDbx_zhs {
	meta:
		description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e34228345498a48d7f529dbdffcd919da2dea414"
	strings:
		$s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
		$s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
		$s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
		$s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
		$s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
		$s12 = "mailto:support@sqldbx.com" fullword ascii
		$s15 = "S.last_login_time \"Last Login\", " fullword ascii
	condition:
		uint16(0) == 0x5a4d and 4 of them
}

rule ms10048_x86 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
	strings:
		$s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
		$s2 = "The target is most likely patched." fullword ascii
		$s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
		$s4 = "[ ] Creating evil window" fullword ascii
		$s5 = "%sHANDLEF_INDESTROY" fullword ascii
		$s6 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule Dos_ch {
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
	strings:
		$s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
		$s4 = "fuck,can't find WMI process PID." fullword ascii
		$s5 = "/Churraskito/-->Found token %s " fullword ascii
		$s8 = "wmiprvse.exe" fullword ascii
		$s10 = "SELECT * FROM IIsWebInfo" fullword ascii
		$s17 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 260KB and 3 of them
}

rule DUBrute_DUBrute {
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"
	strings:
		$s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s4 = "UBrute.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1020KB and all of them
}

rule CookieTools {
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
	strings:
		$s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s8 = "OnGetPasswordP" fullword ascii
		$s12 = "http://www.chinesehack.org/" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule update_PcInit {
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
	strings:
		$s1 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
		$s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
		$s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule dat_NaslLib {
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}

rule Dos_1 {
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
	strings:
		$s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
		$s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule OtherTools_servu {
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii
	condition:
		$s0 at 0 and filesize < 50KB and all of them
}

rule ustrrefadd {
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
	strings:
		$s0 = "E-Mail  : admin@luocong.com" fullword ascii
		$s1 = "Homepage: http://www.luocong.com" fullword ascii
		$s2 = ": %d  -  " fullword ascii
		$s3 = "ustrreffix.dll" fullword ascii
		$s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and all of them
}

rule XScanLib {
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
	strings:
		$s4 = "XScanLib.dll" fullword ascii
		$s6 = "Ports/%s/%d" fullword ascii
		$s8 = "DEFAULT-TCP-PORT" fullword ascii
		$s9 = "PlugCheckTcpPort" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 360KB and all of them
}

rule IDTools_For_WinXP_IdtTool {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"
	strings:
		$s2 = "IdtTool.sys" fullword ascii
		$s4 = "Idt Tool bY tMd[CsP]" fullword wide
		$s6 = "\\\\.\\slIdtTool" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule GoodToolset_ms11046 {
	meta:
		description = "Chinese Hacktool Set - file ms11046.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
	strings:
		$s1 = "[*] Token system command" fullword ascii
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s3 = "[*] Add to Administrators success" fullword ascii
		$s4 = "[*] User has been successfully added" fullword ascii
		$s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 840KB and 2 of them
}

rule Cmdshell32 {
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
	strings:
		$s1 = "cmdshell.exe" fullword wide
		$s2 = "cmdshell" fullword ascii
		$s3 = "[Root@CmdShell ~]#" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule Sniffer_analyzer_SSClone_1210_full_version {
	meta:
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"
	strings:
		$s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
		$s1 = "GetConnectString" fullword ascii
		$s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
		$s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}

rule x64_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "klock.dll" fullword ascii
		$s3 = "Erreur : le bureau courant (" fullword wide
		$s4 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Dos_Down32 {
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 137KB and all of them
}

rule MarathonTool_2 {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Tools_termsrv {
	meta:
		description = "Chinese Hacktool Set - file termsrv.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"
	strings:
		$s1 = "Iv\\SmSsWinStationApiPort" fullword ascii
		$s2 = " TSInternetUser " fullword wide
		$s3 = "KvInterlockedCompareExchange" fullword ascii
		$s4 = " WINS/DNS " fullword wide
		$s5 = "winerror=%1" fullword wide
		$s6 = "TermService " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule scanms_scanms {
	meta:
		description = "Chinese Hacktool Set - file scanms.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"
	strings:
		$s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
		$s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
		$s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
		$s5 = "Internet Explorer 1.0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 3 of them
}

rule CN_Tools_PcShare {
	meta:
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"
	strings:
		$s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
		$s5 = "port=%s;name=%s;pass=%s;" fullword wide
		$s16 = "%s\\ini\\*.dat" fullword wide
		$s17 = "pcinit.exe" fullword wide
		$s18 = "http://www.pcshare.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}

rule pw_inspector {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
	strings:
		$s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
		$s2 = "http://www.thc.org" fullword ascii
		$s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 460KB and all of them
}

rule Dll_LoadEx {
	meta:
		description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"
	strings:
		$s0 = "WiNrOOt@126.com" fullword wide
		$s1 = "Dll_LoadEx.EXE" fullword wide
		$s3 = "You Already Loaded This DLL ! :(" fullword ascii
		$s10 = "Dll_LoadEx Microsoft " fullword wide
		$s17 = "Can't Load This Dll ! :(" fullword ascii
		$s18 = "WiNrOOt" fullword wide
		$s20 = " Dll_LoadEx(&A)..." fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and 3 of them
}

rule dat_report {
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 480KB and all of them
}

rule Dos_iis7 {
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s5 = "WHOAMI" ascii
		$s13 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule SwitchSniffer {
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule dbexpora {
	meta:
		description = "Chinese Hacktool Set - file dbexpora.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b55b007ef091b2f33f7042814614564625a8c79f"
	strings:
		$s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
		$s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
		$s13 = "ORACommand *" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 835KB and all of them
}

rule SQLCracker {
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
	strings:
		$s0 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 125KB and all of them
}

rule FreeVersion_debug {
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
	strings:
		$s0 = "c:\\Documents and Settings\\Administrator\\" fullword ascii
		$s1 = "Got WMI process Pid: %d" ascii
		$s2 = "This exploit will execute" ascii
		$s6 = "Found token %s " ascii
		$s7 = "Running reverse shell" ascii
		$s10 = "wmiprvse.exe" fullword ascii
		$s12 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 820KB and 3 of them
}

rule Dos_look {
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
	strings:
		$s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
		$s2 = "version=\"9.9.9.9\"" fullword ascii
		$s3 = "name=\"CH.Ken.Tool\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule NtGodMode {
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii  /* Goodware String - occured 6 times */
		$s19 = "RtlUnw" fullword ascii /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}

rule Dos_NC {
	meta:
		description = "Chinese Hacktool Set - file NC.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57f0839433234285cc9df96198a6ca58248a4707"
	strings:
		$s1 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
		$s3 = "post-rcv getsockname failed" fullword ascii
		$s4 = "Failed to execute shell, error = %s" fullword ascii
		$s5 = "UDP listen needs -p arg" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 290KB and all of them
}

rule WebCrack4_RouterPasswordCracking {
	meta:
		description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"
	strings:
		$s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
		$s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
		$s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
		$s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
		$s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule HScan_v1_20_oncrpc {
	meta:
		description = "Chinese Hacktool Set - file oncrpc.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e8f047eed8d4f6d2f5dbaffdd0e6e4a09c5298a2"
	strings:
		$s1 = "clnt_raw.c - Fatal header serialization error." fullword ascii
		$s2 = "svctcp_.c - cannot getsockname or listen" fullword ascii
		$s3 = "too many connections (%d), compilation constant FD_SETSIZE was only %d" fullword ascii
		$s4 = "svc_run: - select failed" fullword ascii
		$s5 = "@(#)bindresvport.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 340KB and 4 of them
}

rule hscan_gui {
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule S_MultiFunction_Scanners_s {
	meta:
		description = "Chinese Hacktool Set - file s.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"
	strings:
		$s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
		$s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
		$s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
		$s3 = "explorer.exe http://www.hackdos.com" fullword ascii
		$s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
		$s5 = "Failed to read file or invalid data in file!" fullword ascii
		$s6 = "www.hackdos.com" fullword ascii
		$s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
		$s11 = "The interface of kernel library is invalid!" fullword ascii
		$s12 = "eventvwr" fullword ascii
		$s13 = "Failed to decompress data!" fullword ascii
		$s14 = "NOTEPAD.EXE result.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 8000KB and 4 of them
}

rule Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule update_PcMain {
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
		$s3 = "\\svchost.exe -k " fullword ascii
		$s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
		$s9 = "Global\\%s-key-event" fullword ascii
		$s10 = "%d%d.exe" fullword ascii
		$s14 = "%d.exe" fullword ascii
		$s15 = "Global\\%s-key-metux" fullword ascii
		$s18 = "GET / HTTP/1.1" fullword ascii
		$s19 = "\\Services\\" fullword ascii
		$s20 = "qy001id=%d;qy001guid=%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule Dos_sys {
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule dat_xpf {
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" fullword wide
		$s3 = "\\DosDevices\\XScanPF" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule Project1 {
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
	strings:
		$s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
		$s2 = "Password.txt" fullword ascii
		$s3 = "LoginPrompt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule Arp_EMP_v1_0 {
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Tools_MyUPnP {
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}

rule CN_Tools_Shiell {
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"
	strings:
		$s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
		$s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
		$s3 = "Shift shell.exe" fullword wide
		$s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}

rule cndcom_cndcom {
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"
	strings:
		$s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
		$s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
		$s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
		$s5 = "Windows NT SP6 (Chinese)" fullword ascii
		$s6 = "- Original code by FlashSky and Benjurry" fullword ascii
		$s7 = "\\C$\\123456111111111111111.doc" fullword wide
		$s8 = "shell3all.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule IsDebug_V1_4 {
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
	strings:
		$s0 = "IsDebug.dll" fullword ascii
		$s1 = "SV Dumper V1.0" fullword wide
		$s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
		$s8 = "Error WriteMemory failed" fullword ascii
		$s9 = "IsDebugPresent" fullword ascii
		$s10 = "idb_Autoload" fullword ascii
		$s11 = "Bin Files" fullword ascii
		$s12 = "MASM32 version" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule HTTPSCANNER {
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}

rule HScan_v1_20_PipeCmd {
	meta:
		description = "Chinese Hacktool Set - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "64403ce63b28b544646a30da3be2f395788542d6"
	strings:
		$s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
		$s2 = "PipeCmd.exe" fullword wide
		$s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s4 = "%s\\pipe\\%s%s%d" fullword ascii
		$s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "This is a service executable! Couldn't start directly." fullword ascii
		$s8 = "Connecting to Remote Server ...Failed" fullword ascii
		$s9 = "PIPECMDSRV" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}

rule Dos_fp {
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s2 = "FPipe.exe" fullword wide
		$s3 = "http://www.foundstone.com" fullword ascii
		$s4 = "%s %s port %d. Address is already in use" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 65KB and all of them
}

rule Dos_netstat {
	meta:
		description = "Chinese Hacktool Set - file netstat.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"
	strings:
		$s0 = "w03a2409.dll" fullword ascii
		$s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide  /* Goodware String - occured 2 times */
		$s2 = "Administrative Status  = %1!u!" fullword wide  /* Goodware String - occured 2 times */
		$s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide  /* Goodware String - occured 2 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule CN_Tools_xsniff {
	meta:
		description = "Chinese Hacktool Set - file xsniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule MSSqlPass {
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
	strings:
		$s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
		$s1 = "empv.exe" fullword wide
		$s2 = "Enterprise Manager PassView" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule WSockExpert {
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"
	strings:
		$s1 = "OpenProcessCmdExecute!" fullword ascii
		$s2 = "http://www.hackp.com" fullword ascii
		$s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
		$s4 = "SaveSelectedFilterCmdExecute" fullword ascii
		$s5 = "PasswordChar@" fullword ascii
		$s6 = "WSockHook.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Ms_Viru_racle {
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
	strings:
		$s0 = "PsInitialSystemProcess @%p" fullword ascii
		$s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
		$s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
		$s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 210KB and all of them
}

rule lamescan3 {
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}

rule CN_Tools_pc {
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Dos_Down64 {
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
	strings:
		$s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s3 = "C:\\Windows\\Temp\\" fullword wide
		$s4 = "ProcessXElement" fullword ascii
		$s8 = "down.exe" fullword wide
		$s20 = "set_Timer1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule epathobj_exp32 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"
	strings:
		$s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s1 = "Exploit ok run command" fullword ascii
		$s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" fullword ascii
		$s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s4 = "Mutex object did not timeout, list not patched" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 270KB and all of them
}

rule Tools_unknown {
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
	strings:
		$s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
		$s5 = "Host: 127.0.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule PLUGIN_AJunk {
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
	strings:
		$s1 = "AJunk.dll" fullword ascii
		$s2 = "AJunk.DLL" fullword wide
		$s3 = "AJunk Dynamic Link Library" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 560KB and all of them
}

rule IISPutScanner {
	meta:
		description = "Chinese Hacktool Set - file IISPutScanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"
	strings:
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "ADVAPI32.DLL" fullword ascii
		$s4 = "VERSION.DLL" fullword ascii
		$s5 = "WSOCK32.DLL" fullword ascii
		$s6 = "COMCTL32.DLL" fullword ascii
		$s7 = "GDI32.DLL" fullword ascii
		$s8 = "SHELL32.DLL" fullword ascii
		$s9 = "USER32.DLL" fullword ascii
		$s10 = "OLEAUT32.DLL" fullword ascii
		$s11 = "LoadLibraryA" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "VirtualProtect" fullword ascii
		$s14 = "VirtualAlloc" fullword ascii
		$s15 = "VirtualFree" fullword ascii
		$s16 = "ExitProcess" fullword ascii
		$s17 = "RegCloseKey" fullword ascii
		$s18 = "GetFileVersionInfoA" fullword ascii
		$s19 = "ImageList_Add" fullword ascii
		$s20 = "BitBlt" fullword ascii
		$s21 = "ShellExecuteA" fullword ascii
		$s22 = "ActivateKeyboardLayout" fullword ascii
		$s23 = "BBABORT" fullword wide
		$s25 = "BBCANCEL" fullword wide
		$s26 = "BBCLOSE" fullword wide
		$s27 = "BBHELP" fullword wide
		$s28 = "BBIGNORE" fullword wide
		$s29 = "PREVIEWGLYPH" fullword wide
		$s30 = "DLGTEMPLATE" fullword wide
		$s31 = "TABOUTBOX" fullword wide
		$s32 = "TFORM1" fullword wide
		$s33 = "MAINICON" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and filesize > 350KB and all of them
}

rule IDTools_For_WinXP_IdtTool_2 {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
	strings:
		$s0 = "\\Device\\devIdtTool" fullword wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s6 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
		$s7 = "IoCreateDevice" fullword ascii /* Goodware String - occured 988 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 7KB and all of them
}

rule hkmjjiis6 {
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "user32.dlly" ascii
		$s3 = "runtime error" ascii
		$s4 = "WinSta0\\Defau" ascii
		$s5 = "AppIDFlags" fullword ascii
		$s6 = "GetLag" fullword ascii
		$s7 = "* FROM IIsWebInfo" ascii
		$s8 = "wmiprvse.exe" ascii
		$s9 = "LookupAcc" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Dos_lcx {
	meta:
		description = "Chinese Hacktool Set - file lcx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6ad5dd13592160d9f052bb47b0d6a87b80a406d"
	strings:
		$s0 = "c:\\Users\\careful_snow\\" ascii
		$s1 = "Desktop\\Htran\\Release\\Htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s6 = "=========== Code by lion & bkbll, Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s7 = "[-] There is a error...Create a new connection." fullword ascii
		$s8 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s13 = "[+] Make a Connection to %s:%d...." fullword ascii
		$s16 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
		$s17 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s18 = "[+] Accept a Client on port %d from %s ......" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule x_way2_5_X_way {
	meta:
		description = "Chinese Hacktool Set - file X-way.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"
	strings:
		$s0 = "TTFTPSERVERFRM" fullword wide
		$s1 = "TPORTSCANSETFRM" fullword wide
		$s2 = "TIISSHELLFRM" fullword wide
		$s3 = "TADVSCANSETFRM" fullword wide
		$s4 = "ntwdblib.dll" fullword ascii
		$s5 = "TSNIFFERFRM" fullword wide
		$s6 = "TCRACKSETFRM" fullword wide
		$s7 = "TCRACKFRM" fullword wide
		$s8 = "dbnextrow" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule tools_Sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "99d56476e539750c599f76391d717c51c4955a33"
	strings:
		$s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
		$s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
		$s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
		$s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
		$s10 = "Error,exit!" fullword ascii
		$s11 = "Sqlcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}

rule Sword1_5 {
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" fullword wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule Tools_scan {
	meta:
		description = "Chinese Hacktool Set - file scan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"
	strings:
		$s2 = "Shanlu Studio" fullword wide
		$s3 = "_AutoAttackMain" fullword ascii
		$s4 = "_frmIpToAddr" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Dos_c {
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
		$s9 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule arpsniffer {
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii  /* Goodware String - occured 3 times */
		$s5 = "packet.dll" fullword ascii  /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule pw_inspector_2 {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"
	strings:
		$s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
		$s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s3 = "PW-Inspector" fullword ascii
		$s4 = "i:o:m:M:c:lunps" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule datPcShare {
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
	strings:
		$s1 = "PcShare.EXE" fullword wide
		$s2 = "MZKERNEL32.DLL" fullword ascii
		$s3 = "PcShare" fullword wide
		$s4 = "QQ:4564405" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Tools_xport {
	meta:
		description = "Chinese Hacktool Set - file xport.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"
	strings:
		$s1 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
		$s2 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
		$s3 = "%s - command line port scanner" fullword ascii
		$s4 = "xport 192.168.1.1 1-1024 -t 200 -v" fullword ascii
		$s5 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
		$s6 = ".\\port.ini" fullword ascii
		$s7 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
		$s8 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s9 = "http://www.xfocus.org" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Pc_xai {
	meta:
		description = "Chinese Hacktool Set - file xai.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"
	strings:
		$s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
		$s2 = "%SystemRoot%\\System32\\" fullword ascii
		$s3 = "%APPDATA%\\" fullword ascii
		$s4 = "---- C.Rufus Security Team ----" fullword wide
		$s5 = "www.snzzkz.com" fullword wide
		$s6 = "%CommonProgramFiles%\\" fullword ascii
		$s7 = "GetRand.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Radmin_Hash {
	meta:
		description = "Chinese Hacktool Set - file Radmin_Hash.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"
	strings:
		$s1 = "<description>IEBars</description>" fullword ascii
		$s2 = "PECompact2" fullword ascii
		$s3 = "Radmin, Remote Administrator" fullword wide
		$s4 = "Radmin 3.0 Hash " fullword wide
		$s5 = "HASH1.0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule OSEditor {
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
	strings:
		$s1 = "OSEditor.exe" fullword wide
		$s2 = "netsafe" wide
		$s3 = "OSC Editor" fullword wide
		$s4 = "GIF89" ascii
		$s5 = "Unlock" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule GoodToolset_ms11011 {
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
		$s4 = "SystemDefaultEUDCFont" fullword wide  /* Goodware String - occured 18 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule FreeVersion_release {
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user " ascii
		$s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
		$s4 = "Running reverse shell" ascii
		$s5 = "wmiprvse.exe" fullword ascii
		$s6 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule churrasco {
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
	strings:
		$s1 = "Done, command should have ran as SYSTEM!" ascii
		$s2 = "Running command with SYSTEM Token..." ascii
		$s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
		$s4 = "Found SYSTEM token 0x%x" ascii
		$s5 = "Thread not impersonating, looking for another thread..." ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}
rule x64_KiwiCmd {
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Cmd no-gpo" fullword wide
		$s3 = "KiwiAndCMD" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}

rule sql1433_SQL {
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"
	strings:
		/* WIDE: ProductName 1433 */
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		/* WIDE: ProductVersion 1,4,3,3 */
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }
	condition:
		uint16(0) == 0x5a4d and filesize < 90KB and all of them
}

rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule cyclotron {
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
	strings:
		$s1 = "\\Device\\IDTProt" fullword wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "\\??\\slIDTProt" fullword wide
		$s4 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s5 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 3KB and all of them
}

rule xscan_gui {
	meta:
		description = "Chinese Hacktool Set - file xscan_gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
		$s2 = "www.target.com" fullword ascii
		$s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
		$s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Tools_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
	strings:
		$s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
		$s3 = "%s -h www.target.com -all" fullword ascii
		$s4 = ".\\report\\%s-%s.html" fullword ascii
		$s5 = ".\\log\\Hscan.log" fullword ascii
		$s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
		$s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
		$s8 = ".\\conf\\mysql_pass.dic" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule GoodToolset_pr {
	meta:
		description = "Chinese Hacktool Set - file pr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "-->This exploit gives you a Local System shell " ascii
		$s3 = "wmiprvse.exe" fullword ascii
		$s4 = "Try the first %d time" fullword ascii
		$s5 = "-->Build&&Change By p " ascii
		$s6 = "root\\MicrosoftIISv2" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule hydra_7_4_1_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"
	strings:
		$s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
		$s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
		$s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
		$s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Tools_srss_2 {
	meta:
		description = "Chinese Hacktool Set - file srss.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"
	strings:
		$x1 = "used pepack!" fullword ascii

		$s1 = "KERNEL32.dll" fullword ascii
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii
		$s5 = "VirtualProtect" fullword ascii
		$s6 = "VirtualAlloc" fullword ascii
		$s7 = "VirtualFree" fullword ascii
		$s8 = "ExitProcess" fullword ascii
	condition:
		uint16(0) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ($s*)
}

rule Dos_NtGod {
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Tools_VNCLink {
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}

rule tools_NTCmd {
	meta:
		description = "Chinese Hacktool Set - file NTCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"
	strings:
		$s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
		$s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
		$s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
		$s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii /* PEStudio Blacklist: os */
		$s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
		$s6 = "NTcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and 2 of them
}

rule mysql_pwd_crack {
	meta:
		description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
	strings:
		$s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
		$s2 = "Successfully --> username %s password %s " fullword ascii
		$s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
		$s4 = "-a automode  automatic crack the mysql password " fullword ascii
		$s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule CmdShell64 {
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"
	strings:
		$s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		$s2 = "ServiceCmdShell" fullword ascii
		$s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
		$s4 = "ServiceSystemShell" fullword wide
		$s5 = "[Root@CmdShell ~]#" fullword wide
		$s6 = "Hello Man 2015 !" fullword wide
		$s7 = "CmdShell" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 4 of them
}

rule Ms_Viru_v {
	meta:
		description = "Chinese Hacktool Set - file v.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"
	strings:
		$s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
		$s3 = "OH,Sry.Too long command." fullword ascii
		$s4 = "Success! Commander." fullword ascii
		$s5 = "Hey,how can racle work without ur command ?" fullword ascii
		$s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Tools_Vscan {
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"
	strings:
		$s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
		$s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
		$s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
		$s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and 2 of them
}

rule Dos_iis {
	meta:
		description = "Chinese Hacktool Set - file iis.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "program terming" fullword ascii
		$s3 = "WinSta0\\Defau" fullword ascii
		$s4 = "* FROM IIsWebInfo" ascii
		$s5 = "www.icehack." ascii
		$s6 = "wmiprvse.exe" fullword ascii
		$s7 = "Pid: %d" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule IISPutScannesr {
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Generate {
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
	strings:
		$s1 = "C:\\TEMP\\" fullword ascii
		$s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s3 = "$530 Please login with USER and PASS." fullword ascii
		$s4 = "_Shell.exe" fullword ascii
		$s5 = "ftpcWaitingPassword" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}

rule Pc_rejoice {
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
		$s2 = "http://www.xxx.com/xxx.exe" fullword ascii
		$s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
		$s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s5 = "ListViewProcessListColumnClick!" fullword ascii
		$s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule ms11080_withcmd {
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule OtherTools_xiaoa {
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"
	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s3 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Unable to get kernel base address." fullword ascii
		$s5 = "run \"%s\" failed,code: %d" fullword ascii
		$s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule unknown2 {
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" fullword wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule hydra_7_3_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"
	strings:
		$s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
		$s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
		$s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule OracleScan {
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" fullword ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule SQLTools {
	meta:
		description = "Chinese Hacktool Set - file SQLTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"
	strings:
		$s1 = "DBN_POST" fullword wide
		$s2 = "LOADER ERROR" fullword ascii
		$s3 = "www.1285.net" fullword wide
		$s4 = "TUPFILEFORM" fullword wide
		$s5 = "DBN_DELETE" fullword wide
		$s6 = "DBINSERT" fullword wide
		$s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2350KB and all of them
}

rule portscanner {
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule kappfree {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Smartniff {
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"
	strings:
		$s1 = "smsniff.exe" fullword wide
		$s2 = "support@nirsoft.net0" fullword ascii
		$s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule ChinaChopper_caidao {
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
	strings:
		$s1 = "Pass,Config,n{)" fullword ascii
		$s2 = "phMYSQLZ" fullword ascii
		$s3 = "\\DHLP\\." fullword ascii
		$s4 = "\\dhlp\\." fullword ascii
		$s5 = "SHAutoComple" fullword ascii
		$s6 = "MainFrame" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1077KB and all of them
}

rule KiwiTaskmgr_2 {
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule kappfree_2 {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule x_way2_5_sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"
	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
		$s4 = "kernel32.dll" fullword ascii
		$s5 = "VirtualAlloc" fullword ascii
		$s6 = "VirtualFree" fullword ascii
		$s7 = "VirtualProtect" fullword ascii
		$s8 = "ExitProcess" fullword ascii
		$s9 = "user32.dll" fullword ascii
		$s16 = "MessageBoxA" fullword ascii
		$s10 = "wsprintfA" fullword ascii
		$s11 = "kernel32.dll" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "GetModuleHandleA" fullword ascii
		$s14 = "LoadLibraryA" fullword ascii
		$s15 = "odbc32.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}

rule Win32_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule ipsearcher {
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule ms10048_x64 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
	strings:
		$s1 = "The target is most likely patched." fullword ascii
		$s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
		$s3 = "[ ] Creating evil window" fullword ascii
		$s4 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}

rule hscangui {
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "http://www.cnhonker.com" fullword ascii
		$s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
		$s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule GoodToolset_ms11080 {
	meta:
		description = "Chinese Hacktool Set - file ms11080.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
	strings:
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[*] Add to Administrators success" fullword ascii
		$s5 = "[*] User has been successfully added" fullword ascii
		$s6 = "[>] ms11-08 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule epathobj_exp64 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
	strings:
		$s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s2 = "Exploit ok run command" fullword ascii
		$s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" fullword ascii
		$s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s5 = "Mutex object did not timeout, list not patched" fullword ascii
		$s6 = "- inconsistent onexit begin-end variables" fullword wide  /* Goodware String - occured 96 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule kelloworld_2 {
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule HScan_v1_20_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
		$s3 = ".\\report\\%s-%s.html" fullword ascii
		$s4 = ".\\log\\Hscan.log" fullword ascii
		$s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule _Project1_Generate_rejoice {
	meta:
		description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "sfUserAppDataRoaming" fullword ascii
		$s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
		$s3 = "delphi32.exe" fullword ascii
		$s4 = "hkeyCurrentUser" fullword ascii
		$s5 = "%s is not a valid IP address." fullword wide
		$s6 = "Citadel hooking error" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule _hscan_hscan_hscangui {
	meta:
		description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = ".\\log\\Hscan.log" fullword ascii
		$s2 = ".\\report\\%s-%s.html" fullword ascii
		$s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
		$s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
		$s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and all of them
}

rule kiwi_tools {
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
		hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash10 = "febadc01a64a071816eac61a85418711debaf233"
		hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
		hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
		$s2 = "Benjamin Delpy" fullword ascii
		$s3 = "GlobalSign" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule kiwi_tools_gentil_kiwi {
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash9 = "febadc01a64a071816eac61a85418711debaf233"
		hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "mimikatz" fullword wide
		$s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
		$s3 = "Gentil Kiwi" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}
