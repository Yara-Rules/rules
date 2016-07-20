/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule IronTiger_ASPXSpy
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "ASPXSpy detection. It might be used by other fraudsters"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "ASPXSpy" nocase wide ascii
		$str2 = "IIS Spy" nocase wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
	condition:
		any of ($str*)
}

rule IronTiger_ChangePort_Toolkit_driversinstall : driver 
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Changeport Toolkit driverinstall"	
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "openmydoor" nocase wide ascii
		$str2 = "Install service error" nocase wide ascii
		$str3 = "start remove service" nocase wide ascii
		$str4 = "NdisVersion" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ChangePort_Toolkit_ChangePortExe : Toolkit
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Toolkit ChangePort"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Unable to alloc the adapter!" nocase wide ascii
		$str2 = "Wait for master fuck" nocase wide ascii
		$str3 = "xx.exe <HOST> <PORT>" nocase wide ascii
		$str4 = "chkroot2007" nocase wide ascii
		$str5 = "Door is bind on %s" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_dllshellexc2010 : Backdoor
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "dllshellexc2010 Exchange backdoor + remote shell"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Microsoft.Exchange.Clients.Auth.dll" nocase ascii wide
		$str2 = "Dllshellexc2010" nocase wide ascii
		$str3 = "Users\\ljw\\Documents" nocase wide ascii
		$bla1 = "please input path" nocase wide ascii
		$bla2 = "auth.owa" nocase wide ascii
	condition:
		(uint16(0) == 0x5a4d) and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_dnstunnel : Tunnel
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "\\DnsTunClient\\" nocase wide ascii
		$str2 = "\\t-DNSTunnel\\" nocase wide ascii
		$str3 = "xssok.blogspot" nocase wide ascii
		$str4 = "dnstunclient" nocase wide ascii
		$mistake1 = "because of error, can not analysis" nocase wide ascii
		$mistake2 = "can not deal witn the error" nocase wide ascii
		$mistake3 = "the other retun one RST" nocase wide ascii
		$mistake4 = "Coversation produce one error" nocase wide ascii
		$mistake5 = "Program try to use the have deleted the buffer" nocase wide ascii
	condition:
		(uint16(0) == 0x5a4d) and ((any of ($str*)) or (any of ($mistake*)))
}

rule IronTiger_EFH3_encoder : Encoder
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger EFH3 Encoder"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" nocase wide ascii
		$str2 = "123.EXE 123.EFH" nocase wide ascii
		$str3 = "ENCODER: b[i]: = " nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_GetPassword_x64
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GetPassword x64"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "(LUID ERROR)" nocase wide ascii
		$str2 = "Users\\K8team\\Desktop\\GetPassword" nocase wide ascii
		$str3 = "Debug x64\\GetPassword.pdb" nocase wide ascii
		$bla1 = "Authentication Package:" nocase wide ascii
		$bla2 = "Authentication Domain:" nocase wide ascii
		$bla3 = "* Password:" nocase wide ascii
		$bla4 = "Primary User:" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_GetUserInfo
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GetUserInfo"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "getuserinfo username" nocase wide ascii
		$str2 = "joe@joeware.net" nocase wide ascii
		$str3 = "If . specified for userid," nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_Gh0stRAT_variant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Game Over Good Luck By Wind" nocase wide ascii
		$str2 = "ReleiceName" nocase wide ascii
		$str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
		$str4 = "Winds Update" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_GTalk_Trojan : trojan
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GTalk Trojan"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "gtalklite.com" nocase wide ascii
		$str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" nocase wide ascii
		$str3 = "D13idmAdm" nocase wide ascii
		$str4 = "Error: PeekNamedPipe failed with %i" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTPBrowser_Dropper : Dropper
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - HTTPBrowser Dropper"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = ".dllUT" nocase wide ascii
		$str2 = ".exeUT" nocase wide ascii
		$str3 = ".urlUT" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTP_SOCKS_Proxy_soexe
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "listen SOCKET error." nocase wide ascii
		$str2 = "WSAAsyncSelect SOCKET error." nocase wide ascii
		$str3 = "new SOCKETINFO error!" nocase wide ascii
		$str4 = "Http/1.1 403 Forbidden" nocase wide ascii
		$str5 = "Create SOCKET error." nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (3 of ($str*))
}

rule IronTiger_NBDDos_Gh0stvariant_dropper : Dropper
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "This service can't be stoped." nocase wide ascii
		$str2 = "Provides support for media palyer" nocase wide ascii
		$str4 = "CreaetProcess Error" nocase wide ascii
		$bla1 = "Kill You" nocase wide ascii
		$bla2 = "%4.2f GB" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_PlugX_DosEmulator
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX DosEmulator"	
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Dos Emluator Ver" nocase wide ascii
		$str2 = "\\PIPE\\FASTDOS" nocase wide ascii
		$str3 = "FastDos.cpp" nocase wide ascii
		$str4 = "fail,error code = %d." nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_FastProxy
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX FastProxy"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "SAFEPROXY HTServerTimer Quit!" nocase wide ascii
		$str2 = "Useage: %s pid" nocase wide ascii
		$str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" nocase wide ascii
		$str4 = "p0: port for listener" nocase wide ascii
		$str5 = "\\users\\whg\\desktop\\plug\\" nocase wide ascii
		$str6 = "[+Y] cwnd : %3d, fligth:" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_Server
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX Server"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "\\UnitFrmManagerKeyLog.pas" nocase wide ascii
		$str2 = "\\UnitFrmManagerRegister.pas" nocase wide ascii
		$str3 = "Input Name..." nocase wide ascii
		$str4 = "New Value#" nocase wide ascii
		$str5 = "TThreadRControl.Execute SEH!!!" nocase wide ascii
		$str6 = "\\UnitFrmRControl.pas" nocase wide ascii
		$str7 = "OnSocket(event is error)!" nocase wide ascii
		$str8 = "Make 3F Version Ok!!!" nocase wide ascii
		$str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" nocase wide ascii
		$str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ReadPWD86
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - ReadPWD86"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Fail To Load LSASRV" nocase wide ascii
		$str2 = "Fail To Search LSASS Data" nocase wide ascii
		$str3 = "User Principal" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (all of ($str*))
}

rule IronTiger_Ring_Gh0stvariant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Ring Gh0stvariant"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "RING RAT Exception" nocase wide ascii
		$str2 = "(can not update server recently)!" nocase wide ascii
		$str4 = "CreaetProcess Error" nocase wide ascii
		$bla1 = "Sucess!" nocase wide ascii
		$bla2 = "user canceled!" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_wmiexec
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Tool - wmi.vbs detection"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Temp Result File , Change it to where you like" nocase wide ascii
		$str2 = "wmiexec" nocase wide ascii
		$str3 = "By. Twi1ight" nocase wide ascii
		$str4 = "[both mode] ,delay TIME to read result" nocase wide ascii
		$str5 = "such as nc.exe or Trojan" nocase wide ascii
		$str6 = "+++shell mode+++" nocase wide ascii
		$str7 = "win2008 fso has no privilege to delete file" nocase wide ascii
	condition:
		2 of ($str*)
}
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-09-16
	Identifier: Iron Panda
*/

/* Rule Set ----------------------------------------------------------------- */

rule IronPanda_DNSTunClient {
	meta:
		description = "Iron Panda malware DnsTunClient - file named.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		score = 80
		hash = "a08db49e198068709b7e52f16d00a10d72b4d26562c0d82b4544f8b0fb259431"
	strings:
		$s1 = "dnstunclient -d or -domain <domain>" fullword ascii
		$s2 = "dnstunclient -ip <server ip address>" fullword ascii
		$s3 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"\\Microsoft\\Windows\\PLA\\System\\Microsoft Windows\" /tr " fullword ascii
		$s4 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"Microsoft Windows\" /tr " fullword ascii
		$s5 = "taskkill /im conime.exe" fullword ascii
		$s6 = "\\dns control\\t-DNSTunnel\\DnsTunClient\\DnsTunClient.cpp" fullword ascii
		$s7 = "UDP error:can not bing the port(if there is unclosed the bind process?)" fullword ascii
		$s8 = "use error domain,set domain pls use -d or -domain mark(Current: %s,recv %s)" fullword ascii
		$s9 = "error: packet num error.the connection have condurt,pls try later" fullword ascii
		$s10 = "Coversation produce one error:%s,coversation fail" fullword ascii
		$s11 = "try to add many same pipe to select group(or mark is too easy)." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and 2 of them ) 
		or
		5 of them
}

rule IronPanda_Malware1 {
	meta:
		description = "Iron Panda Malware"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "a0cee5822ddf254c254a5a0b7372c9d2b46b088a254a1208cb32f5fe7eca848a"
	strings:
		$x1 = "activedsimp.dll" fullword wide
		$s1 = "get_BadLoginAddress" fullword ascii
		$s2 = "get_LastFailedLogin" fullword ascii
		$s3 = "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" fullword ascii
		$s4 = "get_PasswordExpirationDate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule IronPanda_Webshell_JSP {
	meta:
		description = "Iron Panda Malware JSP"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"
	strings:
		$s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
		$s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
		$s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
	condition:
		filesize < 330KB and 1 of them
}

rule IronPanda_Malware_Htran {
	meta:
		description = "Iron Panda Malware Htran"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "7903f94730a8508e9b272b3b56899b49736740cea5037ea7dbb4e690bcaf00e7"
	strings:
		$s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
		$s2 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s3 = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s4 = "[-] ERROR: Must supply logfile name." fullword ascii
		$s5 = "[SERVER]connection to %s:%d error" fullword ascii
		$s6 = "[+] Make a Connection to %s:%d...." fullword ascii
		$s7 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s8 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s9 = "[+] Make a Connection to %s:%d ......" fullword ascii
		$s10 = "cmshared_get_ptr_from_atom" fullword ascii
		$s11 = "_cmshared_get_ptr_from_atom" fullword ascii
		$s12 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s13 = "[-] TransmitPort invalid." fullword ascii
		$s14 = "[+] Waiting for Client on port:%d ......" fullword ascii
	condition:
		 ( uint16(0) == 0x5a4d and filesize < 125KB and 3 of them ) 
		 or 
		 5 of them
}

rule IronPanda_Malware2 {
	meta:
		description = "Iron Panda Malware"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "a89c21dd608c51c4bf0323d640f816e464578510389f9edcf04cd34090decc91"
	strings:
		$s0 = "\\setup.exe" fullword ascii
		$s1 = "msi.dll.urlUT" fullword ascii
		$s2 = "msi.dllUT" fullword ascii
		$s3 = "setup.exeUT" fullword ascii
		$s4 = "/c del /q %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule IronPanda_Malware3 {
	meta:
		description = "Iron Panda Malware"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "5cd2af844e718570ae7ba9773a9075738c0b3b75c65909437c43201ce596a742"
	strings:
		$s0 = "PluginDeflater.exe" fullword wide
		$s1 = ".Deflated" fullword wide
		$s2 = "PluginDeflater" fullword ascii
		$s3 = "DeflateStream" fullword ascii /* Goodware String - occured 1 times */
		$s4 = "CompressionMode" fullword ascii /* Goodware String - occured 4 times */
		$s5 = "System.IO.Compression" fullword ascii /* Goodware String - occured 6 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 10KB and all of them
}

rule IronPanda_Malware4 {
	meta:
		description = "Iron Panda Malware"
		author = "Florian Roth"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "0d6da946026154416f49df2283252d01ecfb0c41c27ef3bc79029483adc2240c"
	strings:
		$s0 = "TestPlugin.dll" fullword wide
		$s1 = "<a href='http://www.baidu.com'>aasd</a>" fullword wide
		$s2 = "Zcg.Test.AspxSpyPlugins" fullword ascii
		$s6 = "TestPlugin" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 10KB and all of them
}
