/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"


rule apt_hellsing_implantstrings : PE
{ 
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing implants"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings: 
		$mz="MZ"

		$a1="the file uploaded failed !" 
		$a2="ping 127.0.0.1"
		
		$b1="the file downloaded failed !" 
		$b2="common.asp"
		
		$c="xweber_server.exe" 
		$d="action="

		$debugpath1="d:\\Hellsing\\release\\msger\\" nocase 
		$debugpath2="d:\\hellsing\\sys\\xrat\\" nocase 
		$debugpath3="D:\\Hellsing\\release\\exe\\" nocase 
		$debugpath4="d:\\hellsing\\sys\\xkat\\" nocase 
		$debugpath5="e:\\Hellsing\\release\\clare" nocase 
		$debugpath6="e:\\Hellsing\\release\\irene\\" nocase 
		$debugpath7="d:\\hellsing\\sys\\irene\\" nocase

		$e="msger_server.dll"
		$f="ServiceMain"

	condition:
		($mz at 0) and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}

rule apt_hellsing_installer : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing xweber/msger installers"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back" 

	strings: 
		$mz="MZ"
		
		$cmd="cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
		
		$a1="xweber_install_uac.exe"
		$a2="system32\\cmd.exe" wide
		$a4="S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y=" 
		$a5="S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg=" $a6="7dqm2ODf5N/Y2N/m6+br3dnZpunl44g="
		$a7="vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw==" 
		$a8="vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSI Njl2tyI" $a9="C:\\Windows\\System32\\sysprep\\sysprep.exe" wide 
		$a10="%SystemRoot%\\system32\\cmd.exe" wide 
		$a11="msger_install.dll"
		$a12={00 65 78 2E 64 6C 6C 00}

	condition:
		($mz at 0) and ($cmd and (2 of ($a*))) and filesize < 500000
}

rule apt_hellsing_proxytool : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing proxy testing tool"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back" 

	strings: 
		$mz="MZ"
		$a1="PROXY_INFO: automatic proxy url => %s " 
		$a2="PROXY_INFO: connection type => %d " 
		$a3="PROXY_INFO: proxy server => %s " 
		$a4="PROXY_INFO: bypass list => %s " 
		$a5="InternetQueryOption failed with GetLastError() %d" 
		$a6="D:\\Hellsing\\release\\exe\\exe\\" nocase

	condition:
		($mz at 0) and (2 of ($a*)) and filesize < 300000
}

rule apt_hellsing_xkat : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing xKat tool"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings:
		$mz="MZ"
		$a1="\\Dbgv.sys"
		$a2="XKAT_BIN"
		$a3="release sys file error."
		$a4="driver_load error. "
		$a5="driver_create error."
		$a6="delete file:%s error."
		$a7="delete file:%s ok."
		$a8="kill pid:%d error."
		$a9="kill pid:%d ok."
		$a10="-pid-delete"
		$a11="kill and delete pid:%d error."
		$a12="kill and delete pid:%d ok."

	condition:
		($mz at 0) and (6 of ($a*)) and filesize < 300000
}

rule apt_hellsing_msgertype2 : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing msger type 2 implants"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings:
		$mz="MZ"
		$a1="%s\\system\\%d.txt"
		$a2="_msger"
		$a3="http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4="http://%s/data/%s.1000001000"
		$a5="/lib/common.asp?action=user_upload&file="
		$a6="%02X-%02X-%02X-%02X-%02X-%02X"
	
	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
}

rule apt_hellsing_irene : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing msger irene installer"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings: 
		$mz="MZ"
		$a1="\\Drivers\\usbmgr.tmp" wide
		$a2="\\Drivers\\usbmgr.sys" wide
		$a3="common_loadDriver CreateFile error! " 
		$a4="common_loadDriver StartService error && GetLastError():%d! " 
		$a5="irene" wide
		$a6="aPLib v0.43 - the smaller the better" 

	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
}
