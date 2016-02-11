/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule tran_duy_linh
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.2"
	reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
	date = "01/03/2014"
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$string1 = "Tran Duy Linh" fullword
	$string2 = "DLC Corporation" fullword
condition:
    ($doc at 0) and (all of ($string*))
}

rule misc_iocs
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.1"
	reference = "N/A" 
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$s1 = "dw20.exe"
	$s2 = "cmd /"
condition:
    ($doc at 0) and (1 of ($s*))
}

rule malicious_LNK_files
{
meta:
	author = "@patrickrolsen"
strings:
	$magic = {4C 00 00 00 01 14 02 00} // L.......
	$s1 = "\\RECYCLER\\" wide
	$s2 = "%temp%" wide
	$s3 = "%systemroot%\\system32\\cmd.exe" wide
	//$s4 = "./start" wide
	$s5 = "svchost.exe" wide
	$s6 = "lsass.exe" wide
	$s7 = "csrss.exe" wide
	$s8 = "winlogon.exe" wide
	//$s9 = "%cd%" wide
	$s10 = "%appdata%" wide
	$s11 = "%programdata%" wide
	$s12 = "%localappdata%" wide
	$s13 = ".cpl" wide
condition:
	($magic at 0) and any of ($s*)
}

rule memory_pivy

{
   meta:
	  author = "https://github.com/jackcr/"
   strings:
      $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} // presence of pivy in memory

   condition: 
      any of them

}

rule memory_shylock

{
   meta:
	  author = "https://github.com/jackcr/"

   strings:
      $a = /pipe\\[A-F0-9]{32}/     //Named pipe created by the malware
      $b = /id=[A-F0-9]{32}/     //Portion or the uri beacon
      $c = /MASTER_[A-F0-9]{32}/     //Mutex created by the malware
      $d = "***Load injects by PIPE (%s)" //String found in binary
      $e = "***Load injects url=%s (%s)" //String found in binary
      $f = "*********************** Ping Ok ************************" //String found in binary
      $g = "*** LOG INJECTS *** %s"     //String found in binary

   condition: 
      any of them

}

rule ScanBox_Malware_Generic {
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		author = "Florian Roth"
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"
	strings:
		/* Sample 1 */
		$s0 = "http://142.91.76.134/p.dat" fullword ascii
		$s1 = "HttpDump 1.1" fullword ascii
		
		/* Sample 2 */
		$s3 = "SecureInput .exe" fullword wide
		$s4 = "http://extcitrix.we11point.com/vpn/index.php?ref=1" fullword ascii
		
		/* Sample 3 */
		$s5 = "%SystemRoot%\\System32\\svchost.exe -k msupdate" fullword ascii
		$s6 = "ServiceMaix" fullword ascii		
		
		/* Certificate and Keywords */
		$x1 = "Management Support Team1" fullword ascii
		$x2 = "DTOPTOOLZ Co.,Ltd.0" fullword ascii
		$x3 = "SEOUL1" fullword ascii
	condition:
		( 1 of ($s*) and 2 of ($x*) ) or 
		( 3 of ($x*) )
}

rule TrojanDownloader {
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		author = "Florian Roth"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii
			
		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii						

		$s5 = "SetConsoleMode" fullword ascii		
		$s9 = "TerminateProcess" fullword ascii	
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii		
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii
	condition:
		$x1 and $x2 and ( all of ($s*) ) and filesize < 35000
}


rule Cloaked_as_JPG {
        meta:
                description = "Detects a cloaked file as JPG"
                author = "Florian Roth (eval section from Didier Stevens)"
                date = "2015/02/29"
                score = 70
        strings:
                $ext = "extension: .jpg"
        condition:
                $ext and uint16be(0x00) != 0xFFD8
}



rule rtf_yahoo_ken
{
meta:
	author = "@patrickrolsen"
	maltype = "Yahoo Ken"
	filetype = "RTF"
	version = "0.1"
	description = "Test rule"
	date = "2013-12-14"
strings:
	$magic1 = { 7b 5c 72 74 30 31 } // {\rt01
	$magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
	$magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
	$author1 = { 79 61 68 6f 6f 20 6b 65 63 } // "yahoo ken"
condition:
	($magic1 or $magic2 or $magic3 at 0) and $author1
} 


rule ZXProxy
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	
strings:
	$C = "\\Control\\zxplug" nocase wide ascii
	$h = "http://www.facebook.com/comment/update.exe" wide ascii
	$S = "Shared a shell to %s:%s Successfully" nocase wide ascii
condition:
	any of them
}

rule OrcaRAT
{
    meta:
        Author      = "PwC Cyber Threat Operations"
        Date        = "2014/10/20" 
        Description = "Strings inside"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2014/10/orcarat-a-whale-of-a-tale.html"

    strings:
        $MZ = "MZ"
        $apptype1 = "application/x-ms-application"
        $apptype2 = "application/x-ms-xbap"
        $apptype3 = "application/vnd.ms-xpsdocument"
        $apptype4 = "application/xaml+xml"
        $apptype5 = "application/x-shockwave-flash"
        $apptype6 = "image/pjpeg"
        $err1 = "Set return time error =   %d!"
        $err2 = "Set return time   success!"
        $err3 = "Quit success!"

    condition:
        $MZ at 0 and filesize < 500KB and (all of ($apptype*) and 1 of ($err*))
}

rule EmiratesStatement 
{
	meta:
		Author 		= "Christiaan Beek"
		Date 		= "2013-06-30"
		Description = "Credentials Stealing Attack"
		Reference 	= "https://blogs.mcafee.com/mcafee-labs/targeted-campaign-steals-credentials-in-gulf-states-and-caribbean"
		
		hash0 = "0e37b6efe5de1cc9236017e003b1fc37"
		hash1 = "a28b22acf2358e6aced43a6260af9170"
		hash2 = "6f506d7adfcc2288631ed2da37b0db04"
		hash3 = "8aebade47dc1aa9ac4b5625acf5ade8f"
	
	strings:
		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"
	
	condition:
		all of them
}

rule PUP_InstallRex_AntiFWb {
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth"
		date = "2015-05-13"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		score = 65
	strings:
		$s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
		$s7 = "GetModuleFileName() failed => %u" fullword ascii
		$s8 = "TSULoader.exe" fullword wide
		$s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
		$s17 = "Tsu%08lX.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule LightFTP_fftp_x86_64 {
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 4 of them
}

rule LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide
	condition:
		uint16(0) == 0xfeff and filesize < 1KB and all of them
}

rule SpyGate_v2_9
{
	meta:
		date = "2014/09"
		maltype = "Spygate v2.9 Remote Access Trojan"
		filetype = "exe"
		reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"
	strings:
		$1 = "shutdowncomputer" wide
		$2 = "shutdown -r -t 00" wide
		$3 = "blockmouseandkeyboard" wide
		$4 = "ProcessHacker"
		$5 = "FileManagerSplit" wide
	condition:
		all of them
}

rule PythoRAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PythoRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}

rule VirusRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/VirusRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string0 = "virustotal"
		$string1 = "virusscan"
		$string2 = "abccba"
		$string3 = "pronoip"
		$string4 = "streamWebcam"
		$string5 = "DOMAIN_PASSWORD"
		$string6 = "Stub.Form1.resources"
		$string7 = "ftp://{0}@{1}" wide
		$string8 = "SELECT * FROM moz_logins" wide
		$string9 = "SELECT * FROM moz_disabledHosts" wide
		$string10 = "DynDNS\\Updater\\config.dyndns" wide
		$string11 = "|BawaneH|" wide

	condition:
		all of them
}

rule ice_ix_12xy : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "ICE-IX 1.2.x.y trojan banker"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 
	
	strings:
		$regexp1= /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
		$a = "bn1="
		$b = "&sk1="
		$c = "mario"								//HardDrive GUID artifact
		$d = "FIXME"
		$e = "RFB 003.003"							//VNC artifact
		$ggurl = "http://www.google.com/webhp"

	condition:
		$regexp1 or ($a and $b) or all of ($c,$d,$e,$ggurl) 
}
rule qadars : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Qadars - Mobile part. Maybe Perkele."
		version = "1.0" 
		filetype = "memory"
		ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

	strings:
		$cmd1 = "m?D"
		$cmd2 = "m?S"
		$cmd3 = "ALL"
		$cmd4 = "FILTER"
		$cmd5 = "NONE"
		$cmd6 = "KILL"
		$cmd7 = "CANCEL"
		$cmd8 = "SMS"
		$cmd9 = "DIVERT"
		$cmd10 = "MESS"
		$nofilter = "nofilter1111111"
		$botherderphonenumber1 = "+380678409210"

	condition:
		all of ($cmd*) or $nofilter or any of ($botherderphonenumber*)
}
rule shylock :  banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Shylock Banker"
		date = "2013-12-12" 
		version = "1.0" 
		ref1 = "http://iocbucket.com/iocs/1b4660d57928df5ca843c21df0b2adb117026cba"
		ref2 = "http://www.trusteer.com/blog/merchant-fraud-returns-%E2%80%93-shylock-polymorphic-financial-malware-infections-rise"
		ref3 = "https://www.csis.dk/en/csis/blog/3811/"

	strings:
		$process1 = "MASTER"
		$process2 = "_SHUTDOWN"
		$process3 = "EVT_VNC"
		$process4 = "EVT_BACK"
		$process5 = "EVT_VNC"
		$process6 = "IE_Hook::GetRequestInfo"
		$process7 = "FF_Hook::getRequestInfo"
		$process8 = "EX_Hook::CreateProcess"
		$process9 = "hijackdll.dll"
		$process10 = "MTX_"
		$process11 = "FF::PR_WriteHook entry"
		$process12 = "FF::PR_WriteHook exit"
		$process13 = "HijackProcessAttach::*** MASTER *** MASTER *** MASTER *** %s PID=%u"
		$process14 = "HijackProcessAttach::entry"
		$process15 = "FF::BEFORE INJECT"
		$process16 = "FF::AFTER INJECT"
		$process17 = "IE::AFTER INJECT"
		$process18 = "IE::BEFORE INJECT"
		$process19 = "*** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** %s"
		$process20 = "*** LOG INJECTS *** %s"
		$process21 = "*** inject to process %s not allowed"
		$process22 = "*** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** %s"
		$process23 = ".?AVFF_Hook@@"
		$process24 = ".?AVIE_Hook@@"
		$process25 = "Inject::InjectDllFromMemory"
		$process26 = "BadSocks.dll"	
		$domain1 = "extensadv.cc"
		$domain2 = "topbeat.cc"
		$domain3 = "brainsphere.cc"
		$domain4 = "commonworldme.cc"
		$domain5 = "gigacat.cc"
		$domain6 = "nw-serv.cc"
		$domain7 = "paragua-analyst.cc"
		
	condition:
		3 of ($process*) or any of ($domain*)
}
rule spyeye : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$spyeye = "SpyEye"
		$a = "%BOTNAME%"
		$b = "globplugins"
		$c = "data_inject"
		$d = "data_before"
		$e = "data_after"
		$f = "data_end"
		$g = "bot_version"
		$h = "bot_guid"
		$i = "TakeBotGuid"
		$j = "TakeGateToCollector"
		$k = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
		$l = "[ERROR] : Update is not successfull for some reason"
		$m = "[ERROR] : dwErr == %u"
		$n = "GRABBED DATA"
		
	condition:
		$spyeye or (any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
}

rule spyeye_plugins : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y Plugins memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$a = "webfakes.dll"
		$b = "config.dat"			//may raise some FP
		$c = "collectors.txt"
		$d = "webinjects.txt"
		$e = "screenshots.txt"
		$f = "billinghammer.dll"
		$g = "block.dll"			//may raise some FP
		$h = "bugreport.dll"		//may raise some FP
		$i = "ccgrabber.dll"
		$j = "connector2.dll"
		$k = "creditgrab.dll"
		$l = "customconnector.dll"
		$m = "ffcertgrabber.dll"
		$n = "ftpbc.dll"
		$o = "rdp.dll"				//may raise some FP
		$p = "rt_2_4.dll"
		$q = "socks5.dll"			//may raise some FP
		$r = "spySpread.dll"
		$s = "w2chek4_4.dll"
		$t = "w2chek4_6.dll"
	
	condition:
		any of them
}

rule callTogether_certificate
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the CallTogether certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $serial = { 45 21 56 C3 B3 FB 01 76 36 5B DB 5B 77 15 BC 4C }
        $o = "CallTogether, Inc."

    condition:
        $serial and $o
}

rule qti_certificate
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the QTI International Inc certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $cn = "QTI International Inc"
        $serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }

    condition:
        $cn and $serial
}

rule DownExecute_A
{
	meta:
        Author      = "PwC Cyber Threat Operations :: @tlansec"
        Date        = "2015/04/27"
        Description = "Malware is often wrapped/protected, best to run on memory"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2015/04/attacks-against-israeli-palestinian-interests.html"

    strings:
        $winver1 = "win 8.1"
        $winver2 = "win Server 2012 R2"
        $winver3 = "win Srv 2012"
        $winver4 = "win srv 2008 R2"
        $winver5 = "win srv 2008"
        $winver6 = "win vsta"
        $winver7 = "win srv 2003 R2"
        $winver8 = "win hm srv"
        $winver9 = "win Strg srv 2003"
        $winver10 = "win srv 2003"
        $winver11 = "win XP prof x64 edt"
        $winver12 = "win XP"
        $winver13 = "win 2000"

        $pdb1 = "D:\\Acms\\2\\docs\\Visual Studio 2013\\Projects\\DownloadExcute\\DownloadExcute\\Release\\DownExecute.pdb"
        $pdb2 = "d:\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\writer.h"
        $pdb3 = ":\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\internal/stack.h"
        $pdb4 = "\\downloadexcute\\downexecute\\"

        $magic1 = "<Win Get Version Info Name Error"
        $magic2 = "P@$sw0rd$nd"
        $magic3 = "$t@k0v2rF10w"
        $magic4 = "|*|123xXx(Mutex)xXx321|*|6-21-2014-03:06PM" wide

		$str1 = "Download Excute" ascii wide fullword
        $str2 = "EncryptorFunctionPointer %d"
        $str3 = "%s\\%s.lnk"
        $str4 = "Mac:%s-Cpu:%s-HD:%s"
        $str5 = "feed back responce of host"
        $str6 = "GET Token at host"
        $str7 = "dwn md5 err"

    condition:
        all of ($winver*) or any of ($pdb*) or any of ($magic*) or 2 of ($str*)
}

rule CVE_2015_1674_CNGSYS {
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		reference2 = "https://github.com/Neo23x0/Loki/blob/master/signatures/exploit_cve_2015_1674.yar"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
	strings:
		$s1 = "\\Device\\CNG" fullword wide
		
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule Ap0calypse
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}
rule Arcom
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Arcom"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
        $a1 = "CVu3388fnek3W(3ij3fkp0930di"
        $a2 = "ZINGAWI2"
        $a3 = "clWebLightGoldenrodYellow"
        $a4 = "Ancestor for '%s' not found" wide
        $a5 = "Control-C hit" wide
        $a6 = {A3 24 25 21}
        
    condition:
        all of them
}
rule Bandook
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
    		$a = "aaaaaa1|"
            $b = "aaaaaa2|"
            $c = "aaaaaa3|"
            $d = "aaaaaa4|"
			$e = "aaaaaa5|"
			$f = "%s%d.exe"
			$g = "astalavista"
			$h = "givemecache"
			$i = "%s\\system32\\drivers\\blogs\\*"
			$j = "bndk13me"
			

        
    condition:
    		all of them
}

rule DarkRAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "@1906dark1996coder@"
		$b = "SHEmptyRecycleBinA"
		$c = "mciSendStringA"
		$d = "add_Shutdown"
		$e = "get_SaveMySettingsOnExit"
		$f = "get_SpecialDirectories"
		$g = "Client.My"

	condition:
		all of them
}
rule Greame
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Greame"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
	strings:
    		$a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
            $b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
            $c = "EditSvr"
            $d = "TLoader"
			$e = "Stroks"
            $f = "Avenger by NhT"
			$g = "####@####"
			$h = "GREAME"
			

        
    condition:
    		all of them
}
rule LostDoor
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/LostDoor"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
    	$a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
        $a1 = "*mlt* = %"
        $a2 = "*ip* = %"
        $a3 = "*victimo* = %"
        $a4 = "*name* = %"
        $b5 = "[START]"
        $b6 = "[DATA]"
        $b7 = "We Control Your Digital World" wide ascii
        $b8 = "RC4Initialize" wide ascii
        $b9 = "RC4Decrypt" wide ascii
        
    condition:
    	all of ($a*) or all of ($b*)
}
rule LuxNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/LuxNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}
rule Pandora
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Pandora"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Can't get the Windows version"
		$b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
		$c = "JPEG error #%d" wide
		$d = "Cannot assign a %s to a %s" wide
		$g = "%s, ProgID:"
		$h = "clave"
		$i = "Shell_TrayWnd"
		$j = "melt.bat"
		$k = "\\StubPath"
		$l = "\\logs.dat"
		$m = "1027|Operation has been canceled!"
		$n = "466|You need to plug-in! Double click to install... |"
		$0 = "33|[Keylogger Not Activated!]"

	condition:
		all of them
}
rule Paradox
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Paradox"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ParadoxRAT"
		$b = "Form1"
		$c = "StartRMCam"
		$d = "Flooders"
		$e = "SlowLaris"
		$f = "SHITEMID"
		$g = "set_Remote_Chat"

	condition:
		all of them
}
rule Punisher
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Punisher"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "abccba"
		$b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
		$c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
		$d = "SpyTheSpy" wide ascii
		$e = "wireshark" wide
		$f = "apateDNS" wide
		$g = "abccbaDanabccb"

	condition:
		all of them
}
rule SmallNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/SmallNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and (all of ($a*))
}
rule Base64_encoded_Executable {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 50
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" // 14 samples in goodware archive
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" // 26 samples in goodware archive
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" // 75 samples in goodware archive
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" // 168 samples in goodware archive
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" // 28,529 samples in goodware archive
	condition:
		1 of them
}
rule CredStealESY : For CredStealer
{
 meta:
description = "Generic Rule to detect the CredStealer Malware"
author = "IsecG – McAfee Labs"
date = "2015/05/08"
strings:
$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module
 condition:
$my_hex_string and $my_hex_string2
}
