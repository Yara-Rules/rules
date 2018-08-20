

rule shifu_shiz {
	meta:
		description = "Memory string yara for Shifu/Shiz"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/"
		reference2 = "https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46"
    reference3 = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar"
		date = "2018-03-16"
		maltype1 = "Banker"
		maltype2 = "Keylogger"
		maltype3 = "Stealer"
		filetype = "memory"

	strings:
		$aa = "auth_loginByPassword"	fullword ascii
		$ab = "back_command"	fullword ascii
		$ac = "back_custom1"	fullword ascii
		$ad = "GetClipboardData"	fullword ascii
		$ae = "iexplore.exe|opera.exe|java.exe|javaw.exe|explorer.exe|isclient.exe|intpro.exe|ipc_full.exe"	fullword ascii
		$af = "mnp.exe|cbsmain.dll|firefox.exe|clmain.exe|core.exe|maxthon.exe|avant.exe|safari.exe"	fullword ascii
		$ag = "svchost.exe|chrome.exe|notepad.exe|rundll32.exe|netscape.exe|tbb-firefox.exe|frd.exe"	fullword ascii
		$ah = "!inject"	fullword ascii
		$ai = "!deactivebc"	fullword ascii
		$aj = "!kill_os"	fullword ascii
		$ak = "!load"	fullword ascii
		$al = "!new_config"	fullword ascii
		$am = "!activebc"	fullword ascii
		$an = "keylog.txt"	fullword ascii
		$ao = "keys_path.txt"	fullword ascii
		$ap = "pass.log"	fullword ascii
		$aq = "passwords.txt"	fullword ascii
		$ar = "Content-Disposition: form-data; name=\"file\"; filename=\"report\""	fullword ascii
		$as = "Content-Disposition: form-data; name=\"pcname\""	fullword ascii
		$at = "botid=%s&ver="	fullword ascii
		$au = "action=auth&np=&login="	fullword ascii
		$av = "&ctl00%24MainMenu%24Login1%24UserName="	fullword ascii
		$aw = "&cvv="	fullword ascii
		$ax = "&cvv2="	fullword ascii
		$ay = "&domain="	fullword ascii
		$az = "LOGIN_AUTHORIZATION_CODE="	fullword ascii
		$ba = "name=%s&port=%u"	fullword ascii
		$bb = "PeekNamedPipe"	fullword ascii
		$bc = "[pst]"	fullword ascii
		$bd = "[ret]"	fullword ascii
		$be = "[tab]"	fullword ascii
		$bf = "[bks]"	fullword ascii
		$bg = "[del]"	fullword ascii
		$bh = "[ins]"	fullword ascii
		$bi = "&up=%u&os=%03u&rights=%s&ltime=%s%d&token=%d&cn="	fullword ascii

	condition:
		18 of them
}
