/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

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
